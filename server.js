require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase ─────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ── Email (Resend) ───────────────────────────────────────
// Configure no Railway:
//   RESEND_API_KEY  = a chave da API do Resend (re_...)
//   EMAIL_FROM      = ex: "Trampo <nao-responda@seudominio.com.br>"
//   APP_URL         = ex: https://trampo917.netlify.app  (base dos links)
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM     = process.env.EMAIL_FROM || 'Trampo <onboarding@resend.dev>';
const APP_URL        = process.env.APP_URL || 'https://trampo917.netlify.app';

async function enviarEmail(para, assunto, html) {
  // Sem chave configurada → não envia (modo dev). Retorna false sem quebrar.
  if (!RESEND_API_KEY) {
    console.warn('[email] RESEND_API_KEY não configurada — email não enviado para', para);
    return false;
  }
  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from: EMAIL_FROM, to: [para], subject: assunto, html }),
    });
    if (!resp.ok) {
      const txt = await resp.text();
      console.error('[email] Falha ao enviar:', resp.status, txt);
      return false;
    }
    return true;
  } catch (e) {
    console.error('[email] Erro:', e.message);
    return false;
  }
}

// Template do email de recuperação de senha
function emailRecuperacaoSenha(nome, link) {
  return `
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;background:#F8FAFC;border-radius:12px;overflow:hidden;border:1px solid #E2E8F0">
  <div style="background:#0F172A;padding:24px;text-align:center">
    <span style="font-family:Georgia,serif;font-size:26px;font-weight:700;color:#10B981">trampo</span>
  </div>
  <div style="padding:32px 28px">
    <h1 style="font-size:20px;color:#0F172A;margin:0 0 16px">Redefinição de senha</h1>
    <p style="font-size:15px;color:#334155;line-height:1.6;margin:0 0 12px">Olá${nome ? ', ' + nome : ''}!</p>
    <p style="font-size:15px;color:#334155;line-height:1.6;margin:0 0 24px">Recebemos um pedido para redefinir a senha da sua conta no Trampo. Clique no botão abaixo para criar uma nova senha:</p>
    <div style="text-align:center;margin:0 0 24px">
      <a href="${link}" style="display:inline-block;background:#10B981;color:#FFFFFF;text-decoration:none;padding:14px 32px;border-radius:12px;font-weight:700;font-size:16px">Redefinir senha</a>
    </div>
    <p style="font-size:13px;color:#64748B;line-height:1.6;margin:0 0 8px">Este link expira em 1 hora. Se você não pediu para redefinir sua senha, ignore este email — sua conta continua segura.</p>
    <p style="font-size:13px;color:#64748B;line-height:1.6;margin:0">Se o botão não funcionar, copie e cole este endereço no navegador:<br><span style="color:#10B981;word-break:break-all">${link}</span></p>
  </div>
  <div style="background:#0F172A;padding:16px;text-align:center">
    <p style="font-size:12px;color:#94A3B8;margin:0">Trampo — Serviços e autônomos perto de você</p>
  </div>
</div>`;
}


// ── Middlewares ───────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // serve o formulário HTML

// ── Auth middleware ───────────────────────────────────────
function autenticar(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não informado.' });
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido.' });
  }
}

// ── Validação de UUID ─────────────────────────────────────
// Garante que IDs vindos da URL (req.params) são UUIDs válidos antes de
// usá-los em queries — especialmente importante em filtros .or() que
// concatenam strings. Bloqueia parâmetros forjados.
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function ehUUID(valor) {
  return typeof valor === 'string' && UUID_REGEX.test(valor);
}

// ════════════════════════════════════════════════════════
//  PRÉ-CADASTRO (formulário de divulgação)
// ════════════════════════════════════════════════════════
app.post('/pre-cadastro', async (req, res) => {
  const { nome, email, telefone, cidade, bairro, categoria,
          especialidade, preco_medio, disponibilidade,
          bio, como_soube } = req.body;

  if (!nome || !telefone || !bairro || !categoria) {
    return res.status(400).json({ erro: 'Campos obrigatórios faltando.' });
  }

  const { data, error } = await supabase
    .from('pre_cadastros')
    .insert([{ nome, email, telefone, cidade, bairro, categoria,
               especialidade, preco_medio, disponibilidade,
               bio, como_soube }])
    .select();

  if (error) return res.status(500).json({ erro: error.message });
  res.status(201).json({ mensagem: 'Pré-cadastro realizado!', id: data[0].id });
});

// ════════════════════════════════════════════════════════
//  AUTÔNOMOS — cadastro completo
// ════════════════════════════════════════════════════════
app.post('/autonomos/cadastro', async (req, res) => {
  const { nome, email, senha, telefone, bairro,
          categoria, especialidade, bio, preco_medio,
          disponibilidade, lat, lng, cpf, cidade } = req.body;

  if (!nome || !email || !senha || !telefone || !categoria) {
    return res.status(400).json({ erro: 'Campos obrigatórios faltando.' });
  }

  // Verifica se email já existe
  const { data: existe } = await supabase
    .from('autonomos').select('id').eq('email', email).single();
  if (existe) return res.status(409).json({ erro: 'Email já cadastrado.' });

  const senha_hash = await bcrypt.hash(senha, 10);

  // Monta ponto geográfico se tiver lat/lng
  const localizacao = (lat && lng)
    ? `POINT(${lng} ${lat})`
    : null;

  const { data, error } = await supabase
    .from('autonomos')
    .insert([{ nome, email, senha_hash, telefone, bairro,
               categoria, especialidade, bio, preco_medio,
               disponibilidade, lat, lng, localizacao,
               ...(cpf ? { cpf } : {}),
               ...(cidade ? { cidade } : {}) }])
    .select('id, nome, email, categoria');

  if (error) return res.status(500).json({ erro: error.message });

  const token = jwt.sign(
    { id: data[0].id, tipo: 'autonomo' },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.status(201).json({ mensagem: 'Cadastro realizado!', autonomo: data[0], token });
});

// ── Login do autônomo ─────────────────────────────────────
app.post('/autonomos/login', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'Email e senha obrigatórios.' });

  const { data: autonomo } = await supabase
    .from('autonomos').select('*').eq('email', email).single();

  if (!autonomo || !(await bcrypt.compare(senha, autonomo.senha_hash))) {
    return res.status(401).json({ erro: 'Email ou senha incorretos.' });
  }

  const token = jwt.sign(
    { id: autonomo.id, tipo: 'autonomo' },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  const { senha_hash, ...semSenha } = autonomo;
  res.json({ autonomo: semSenha, token });
});

// ── Buscar autônomos (com filtros e GPS) ─────────────────
app.get('/autonomos', async (req, res) => {
  const { categoria, lat, lng, raio = 10, busca, cidade } = req.query;

  // Busca por GPS (função do banco)
  if (lat && lng) {
    const { data, error } = await supabase.rpc('buscar_autonomos_perto', {
      lat_usuario:      parseFloat(lat),
      lng_usuario:      parseFloat(lng),
      raio_km:          parseFloat(raio),
      categoria_filtro: categoria || null
    });
    if (error) return res.status(500).json({ erro: error.message });
    return res.json(data);
  }

  // Busca simples por categoria / nome
  let query = supabase
    .from('autonomos')
    .select('id, nome, categoria, especialidade, bairro, nota_media, total_avaliacoes, verificado, preco_medio, lat, lng, disponibilidade_dias, ativo')
    .eq('ativo', true)
    .order('nota_media', { ascending: false });

  if (categoria) query = query.eq('categoria', categoria);
  if (cidade)    query = query.eq('cidade', cidade);
  if (busca)     query = query.ilike('nome', `%${busca}%`);

  const { data, error } = await query;
  if (error) return res.status(500).json({ erro: error.message });
  res.json(data);
});

// ── Perfil público do autônomo ────────────────────────────
app.get('/autonomos/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('autonomos')
    .select(`
      id, nome, categoria, especialidade, bairro, bio,
      nota_media, total_avaliacoes, total_servicos,
      verificado, disponibilidade, disponibilidade_dias, disponibilidade_horas, preco_medio,
      servicos ( id, nome, descricao, preco, unidade ),
      avaliacoes ( nota, comentario, criado_em,
        usuarios ( nome ) )
    `)
    .eq('id', req.params.id)
    .eq('ativo', true)
    .single();

  if (error || !data) return res.status(404).json({ erro: 'Autônomo não encontrado.' });
  res.json(data);
});

// ── Painel do autônomo (dados privados) ───────────────────
app.get('/autonomos/painel/dados', autenticar, async (req, res) => {
  const { data, error } = await supabase
    .from('autonomos')
    .select('*, servicos(*)')
    .eq('id', req.usuario.id)
    .single();

  if (error) return res.status(500).json({ erro: error.message });
  const { senha_hash, ...semSenha } = data;
  res.json(semSenha);
});

// ── Métricas do painel ────────────────────────────────────
app.get('/autonomos/painel/metricas', autenticar, async (req, res) => {
  const id = req.usuario.id;
  const seteDiasAtras = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const [pedidos, avaliacoes] = await Promise.all([
    supabase.from('pedidos').select('valor_servico, status, criado_em')
      .eq('autonomo_id', id).gte('criado_em', seteDiasAtras),
    supabase.from('avaliacoes').select('nota, comentario, criado_em, usuarios(nome)')
      .eq('autonomo_id', id).order('criado_em', { ascending: false }).limit(5)
  ]);

  const concluidos  = (pedidos.data || []).filter(p => p.status === 'concluido');
  const faturamento = concluidos.reduce((s, p) => s + p.valor_servico, 0);

  res.json({
    pedidos_semana:    (pedidos.data || []).length,
    concluidos_semana: concluidos.length,
    faturamento_semana: faturamento,
    avaliacoes_recentes: avaliacoes.data || []
  });
});


// ── Estatísticas detalhadas do autônomo ───────────────────
app.get('/autonomos/painel/estatisticas', autenticar, async (req, res) => {
  const id = req.usuario.id;

  const [pedidos, avaliacoes] = await Promise.all([
    supabase.from('pedidos').select('valor_servico, status, criado_em, concluido_em')
      .eq('autonomo_id', id),
    supabase.from('avaliacoes').select('nota, criado_em')
      .eq('autonomo_id', id)
  ]);

  const todosPedidos = pedidos.data || [];
  const todasAval = avaliacoes.data || [];
  const concluidos = todosPedidos.filter(p => p.status === 'concluido');

  // Faturamento total e ganhos (90%)
  const faturamentoTotal = concluidos.reduce((s,p)=>s+parseFloat(p.valor_servico||0),0);
  const ganhosTotal = faturamentoTotal * 0.9;

  // Últimos 6 meses
  const meses = [];
  const agora = new Date();
  for (let i = 5; i >= 0; i--) {
    const mes = new Date(agora.getFullYear(), agora.getMonth() - i, 1);
    const mesFim = new Date(agora.getFullYear(), agora.getMonth() - i + 1, 1);
    const pedidosMes = concluidos.filter(p => {
      const d = new Date(p.concluido_em || p.criado_em);
      return d >= mes && d < mesFim;
    });
    const fatMes = pedidosMes.reduce((s,p)=>s+parseFloat(p.valor_servico||0),0);
    meses.push({
      mes: mes.toLocaleDateString('pt-BR', { month: 'short' }),
      pedidos: pedidosMes.length,
      faturamento: parseFloat(fatMes.toFixed(2)),
      ganhos: parseFloat((fatMes * 0.9).toFixed(2)),
    });
  }

  // Nota média
  const notaMedia = todasAval.length > 0
    ? (todasAval.reduce((s,a)=>s+a.nota,0) / todasAval.length).toFixed(1)
    : 0;

  // Taxa de conclusão
  const taxaConclusao = todosPedidos.length > 0
    ? Math.round((concluidos.length / todosPedidos.length) * 100)
    : 0;

  // Ticket médio
  const ticketMedio = concluidos.length > 0
    ? (faturamentoTotal / concluidos.length).toFixed(2)
    : 0;

  res.json({
    faturamento_total: parseFloat(faturamentoTotal.toFixed(2)),
    ganhos_total: parseFloat(ganhosTotal.toFixed(2)),
    total_pedidos: todosPedidos.length,
    total_concluidos: concluidos.length,
    nota_media: parseFloat(notaMedia),
    total_avaliacoes: todasAval.length,
    taxa_conclusao: taxaConclusao,
    ticket_medio: parseFloat(ticketMedio),
    grafico_meses: meses,
  });
});

// ── Atualizar perfil do autônomo ──────────────────────────
app.put('/autonomos/painel/perfil', autenticar, async (req, res) => {
  const campos = ['telefone','bairro','bio','preco_medio','disponibilidade','ativo','especialidade','chave_pix','disponibilidade_dias','disponibilidade_horas','cpf'];
  const update = {};
  campos.forEach(c => { if (req.body[c] !== undefined) update[c] = req.body[c]; });

  const { data, error } = await supabase
    .from('autonomos').update(update).eq('id', req.usuario.id).select();

  if (error) return res.status(500).json({ erro: error.message });
  res.json({ mensagem: 'Perfil atualizado!', autonomo: data[0] });
});

// ════════════════════════════════════════════════════════
//  USUÁRIOS (clientes)
// ════════════════════════════════════════════════════════
app.post('/usuarios/cadastro', async (req, res) => {
  const { nome, email, senha, telefone, cpf } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Campos obrigatórios faltando.' });

  const { data: existe } = await supabase
    .from('usuarios').select('id').eq('email', email).single();
  if (existe) return res.status(409).json({ erro: 'Email já cadastrado.' });

  const senha_hash = await bcrypt.hash(senha, 10);
  const novoUsuario = { nome, email, senha_hash, telefone };
  if (cpf) novoUsuario.cpf = cpf; // salva o CPF já no cadastro (evita pedir de novo no pagamento)
  const { data, error } = await supabase
    .from('usuarios').insert([novoUsuario]).select('id, nome, email, telefone, cpf');

  if (error) return res.status(500).json({ erro: error.message });

  const token = jwt.sign({ id: data[0].id, tipo: 'usuario' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({ usuario: data[0], token });
});

app.post('/usuarios/login', async (req, res) => {
  const { email, senha } = req.body;
  const { data: usuario } = await supabase.from('usuarios').select('*').eq('email', email).single();
  if (!usuario || !(await bcrypt.compare(senha, usuario.senha_hash)))
    return res.status(401).json({ erro: 'Email ou senha incorretos.' });

  const token = jwt.sign({ id: usuario.id, tipo: 'usuario' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  const { senha_hash, ...semSenha } = usuario;
  res.json({ usuario: semSenha, token });
});

// ════════════════════════════════════════════════════════
//  PEDIDOS
// ════════════════════════════════════════════════════════
app.post('/pedidos', autenticar, async (req, res) => {
  const { autonomo_id, servico_id, descricao, data_agendada, observacao, metodo_pagamento, data_agendamento, hora_agendamento, endereco_servico } = req.body;
  if (!autonomo_id || !servico_id) return res.status(400).json({ erro: 'Dados do serviço obrigatórios.' });

  // Busca preço do serviço
  const { data: servico } = await supabase
    .from('servicos').select('preco').eq('id', servico_id).single();
  if (!servico) return res.status(404).json({ erro: 'Serviço não encontrado.' });

  const valor_servico   = servico.preco;
  const taxa_plataforma = parseFloat((valor_servico * 0.10).toFixed(2));
  const valor_total     = valor_servico; // cliente paga o preço cheio, taxa sai do autônomo

  const { data, error } = await supabase.from('pedidos').insert([{
    usuario_id:  req.usuario.id,
    autonomo_id, servico_id, descricao,
    data_agendada: data_agendamento || data_agendada || null,
    hora_agendamento: hora_agendamento || null,
    observacao: observacao || null,
    endereco_servico: endereco_servico || null,
    metodo_pagamento: metodo_pagamento || 'pix',
    valor_servico, taxa_plataforma, valor_total
  }]).select();

  if (error) return res.status(500).json({ erro: error.message });
  res.status(201).json({ pedido: data[0] });
});

// ── Confirmar conclusão (libera pagamento) ────────────────
app.patch('/pedidos/:id/concluir', autenticar, async (req, res) => {
  const { data: pedido } = await supabase
    .from('pedidos').select('*').eq('id', req.params.id).single();

  if (!pedido) return res.status(404).json({ erro: 'Pedido não encontrado.' });
  if (pedido.usuario_id !== req.usuario.id) return res.status(403).json({ erro: 'Sem permissão.' });
  if (pedido.status !== 'em_andamento') return res.status(400).json({ erro: 'Pedido não está em andamento.' });

  // Update condicional (só conclui se ainda estiver em_andamento) — evita
  // que dois cliques simultâneos, ou o job de 48h, concluam o mesmo pedido 2x.
  const { data, error } = await supabase
    .from('pedidos')
    .update({ status: 'concluido', concluido_em: new Date().toISOString(), transferido: false })
    .eq('id', req.params.id)
    .eq('status', 'em_andamento')
    .select();

  if (error) return res.status(500).json({ erro: error.message });
  if (!data || data.length === 0) {
    return res.status(400).json({ erro: 'Pedido já foi concluído ou não está em andamento.' });
  }

  // Incrementa contador de serviços do autônomo
  await supabase.rpc('incrementar_servicos', { autonomo_id: pedido.autonomo_id });

  // Transferir automaticamente pro autônomo via Asaas
  try {
    const { data: autonomo } = await supabase
      .from('autonomos').select('chave_pix, nome').eq('id', pedido.autonomo_id).single();
    if (autonomo) {
      await transferirAutonomo({ ...pedido, autonomos: autonomo });
    }
  } catch(e) {
    console.log('Erro transferência:', e.message);
  }

  res.json({ mensagem: 'Serviço concluído! Pagamento liberado.', pedido: data[0] });
});

// ── Listar pedidos do usuário ─────────────────────────────
app.get('/pedidos', autenticar, async (req, res) => {
  const campo = req.usuario.tipo === 'autonomo' ? 'autonomo_id' : 'usuario_id';
  const { data, error } = await supabase
    .from('pedidos')
    .select('*, servicos(nome), autonomos(nome, especialidade, categoria, telefone), usuarios(nome, telefone), avaliacoes(nota, comentario)')
    .eq(campo, req.usuario.id)
    .order('criado_em', { ascending: false });

  if (error) return res.status(500).json({ erro: error.message });
  res.json(data);
});

// ════════════════════════════════════════════════════════
//  AVALIAÇÕES
// ════════════════════════════════════════════════════════
app.post('/avaliacoes', autenticar, async (req, res) => {
  const { pedido_id, nota, comentario } = req.body;
  if (!pedido_id || !nota) return res.status(400).json({ erro: 'Pedido e nota obrigatórios.' });
  if (nota < 1 || nota > 5) return res.status(400).json({ erro: 'Nota deve ser entre 1 e 5.' });

  const { data: pedido } = await supabase
    .from('pedidos').select('*').eq('id', pedido_id).single();
  if (!pedido || pedido.status !== 'concluido')
    return res.status(400).json({ erro: 'Só é possível avaliar pedidos concluídos.' });

  const { data, error } = await supabase.from('avaliacoes').insert([{
    pedido_id, nota, comentario,
    usuario_id:  pedido.usuario_id,
    autonomo_id: pedido.autonomo_id
  }]).select();

  if (error) return res.status(500).json({ erro: error.message });
  res.status(201).json({ avaliacao: data[0] });
});

// ════════════════════════════════════════════════════════
//  SERVIÇOS DO AUTÔNOMO
// ════════════════════════════════════════════════════════
app.post('/servicos', autenticar, async (req, res) => {
  const { nome, descricao, preco, unidade } = req.body;
  if (!nome || !preco) return res.status(400).json({ erro: 'Nome e preço obrigatórios.' });

  const { data, error } = await supabase.from('servicos').insert([{
    autonomo_id: req.usuario.id, nome, descricao,
    preco: parseFloat(preco), unidade: unidade || 'serviço'
  }]).select();

  if (error) return res.status(500).json({ erro: error.message });
  res.status(201).json({ servico: data[0] });
});

app.delete('/servicos/:id', autenticar, async (req, res) => {
  const { error } = await supabase
    .from('servicos').delete()
    .eq('id', req.params.id).eq('autonomo_id', req.usuario.id);
  if (error) return res.status(500).json({ erro: error.message });
  res.json({ mensagem: 'Serviço removido.' });
});

// ════════════════════════════════════════════════════════
//  CATEGORIAS
// ════════════════════════════════════════════════════════
app.get('/categorias', async (req, res) => {
  const categorias = [
    { nome: 'Casa & Construção', icone: '🏠', descricao: 'Elétrica, hidráulica, pintura, marcenaria...' },
    { nome: 'Limpeza',           icone: '🧹', descricao: 'Diarista, limpeza pós-obra, dedetização...' },
    { nome: 'Tecnologia',        icone: '💻', descricao: 'TI, celular, CFTV, redes...' },
    { nome: 'Saúde & Bem-estar', icone: '💆', descricao: 'Personal trainer, nutrição, cuidador...' },
    { nome: 'Eventos',           icone: '📸', descricao: 'Fotógrafo, DJ, decoração, buffet...' },
    { nome: 'Pets',              icone: '🐾', descricao: 'Banho, tosa, veterinário, passeador...' },
    { nome: 'Aulas',             icone: '📚', descricao: 'Reforço, inglês, música, CNH...' },
    { nome: 'Beleza',            icone: '✂️',  descricao: 'Cabeleireiro, manicure, maquiagem...' }
  ];

  // Conta autônomos por categoria
  const { data } = await supabase
    .from('autonomos').select('categoria').eq('ativo', true);

  const contagem = (data || []).reduce((acc, a) => {
    acc[a.categoria] = (acc[a.categoria] || 0) + 1;
    return acc;
  }, {});

  res.json(categorias.map(c => ({ ...c, total: contagem[c.nome] || 0 })));
});

// ════════════════════════════════════════════════════════
//  CHAT
// ════════════════════════════════════════════════════════
app.post('/mensagens', autenticar, async (req, res) => {
  const { para_id, para_tipo, texto, pedido_id } = req.body;
  if (!para_id || !para_tipo || !texto?.trim())
    return res.status(400).json({ erro: 'Campos obrigatórios faltando.' });

  const { data, error } = await supabase.from('mensagens').insert([{
    de_id:    req.usuario.id,
    de_tipo:  req.usuario.tipo,
    para_id,
    para_tipo,
    texto:    texto.trim(),
    pedido_id: pedido_id || null,
  }]).select();

  if (error) return res.status(500).json({ erro: error.message });

  // Enviar push para o destinatário
  try {
    const tabela = para_tipo === 'cliente' ? 'usuarios' : 'autonomos';
    const { data: dest } = await supabase.from(tabela).select('push_token').eq('id', para_id).single();
    if (dest?.push_token) {
      // Buscar nome real do remetente (o JWT só guarda id e tipo)
      const tabelaRemetente = req.usuario.tipo === 'autonomo' ? 'autonomos' : 'usuarios';
      const { data: remet } = await supabase.from(tabelaRemetente).select('nome').eq('id', req.usuario.id).single();
      const remetente = remet?.nome || 'Nova mensagem';
      enviarPush(dest.push_token, `💬 ${remetente}`, texto.trim().slice(0,100), { tipo: 'mensagem', de_id: req.usuario.id });
    }
  } catch {}

  res.status(201).json({ mensagem: data[0] });
});

app.get('/mensagens/:outro_id', autenticar, async (req, res) => {
  const meuId   = req.usuario.id;
  const outroId = req.params.outro_id;

  // Validar que outroId é um UUID válido antes de usar no filtro .or()
  if (!ehUUID(outroId)) return res.status(400).json({ erro: 'ID inválido.' });

  const { data, error } = await supabase
    .from('mensagens')
    .select('*')
    .or(`and(de_id.eq.${meuId},para_id.eq.${outroId}),and(de_id.eq.${outroId},para_id.eq.${meuId})`)
    .order('criado_em', { ascending: true });

  if (error) return res.status(500).json({ erro: error.message });

  await supabase.from('mensagens')
    .update({ lida: true })
    .eq('para_id', meuId)
    .eq('de_id', outroId);

  res.json(data);
});


app.get('/mensagens/nao-lidas/total', autenticar, async (req, res) => {
  const { count } = await supabase
    .from('mensagens')
    .select('*', { count: 'exact', head: true })
    .eq('para_id', req.usuario.id)
    .eq('lida', false);
  res.json({ total: count || 0 });
});

app.get('/conversas', autenticar, async (req, res) => {
  const meuId = req.usuario.id;
  const { data, error } = await supabase
    .from('mensagens')
    .select('*')
    .or(`de_id.eq.${meuId},para_id.eq.${meuId}`)
    .order('criado_em', { ascending: false });

  if (error) return res.status(500).json({ erro: error.message });

  // Agrupar pela conversa (última mensagem de cada par)
  const conversas = {};
  (data || []).forEach(m => {
    const outroId = m.de_id === meuId ? m.para_id : m.de_id;
    if (!conversas[outroId]) {
      const outroTipo = m.de_id === meuId ? m.para_tipo : m.de_tipo;
      conversas[outroId] = { ...m, outro_id: outroId, outro_tipo: outroTipo };
    }
  });

  // Buscar o nome de cada participante (separa por tabela)
  const lista = Object.values(conversas);
  const idsUsuarios = lista.filter(c => c.outro_tipo !== 'autonomo').map(c => c.outro_id);
  const idsAutonomos = lista.filter(c => c.outro_tipo === 'autonomo').map(c => c.outro_id);

  const nomes = {};
  if (idsUsuarios.length) {
    const { data: us } = await supabase.from('usuarios').select('id, nome').in('id', idsUsuarios);
    (us || []).forEach(u => { nomes[u.id] = u.nome; });
  }
  if (idsAutonomos.length) {
    const { data: aus } = await supabase.from('autonomos').select('id, nome').in('id', idsAutonomos);
    (aus || []).forEach(a => { nomes[a.id] = a.nome; });
  }

  // Anexar o nome em cada conversa
  lista.forEach(c => { c.outro_nome = nomes[c.outro_id] || 'Usuário'; });

  res.json(lista);
});

// ════════════════════════════════════════════════════════
//  RECUPERAÇÃO DE SENHA
// ════════════════════════════════════════════════════════
app.post('/recuperar-senha', async (req, res) => {
  const { email, tipo } = req.body;
  if (!email) return res.status(400).json({ erro: 'Email obrigatório.' });
  const tabela = tipo === 'autonomo' ? 'autonomos' : 'usuarios';
  const { data } = await supabase.from(tabela).select('id, nome, email').eq('email', email).single();

  // Resposta sempre genérica (não revela se o email existe — boa prática de segurança)
  const respostaGenerica = { mensagem: 'Se o email estiver cadastrado, você receberá as instruções em instantes.' };

  if (!data) return res.json(respostaGenerica);

  const token = jwt.sign(
    { id: data.id, tipo: tipo || 'usuario', acao: 'recuperar_senha' },
    process.env.JWT_SECRET, { expiresIn: '1h' }
  );

  // Link para a página web de redefinição (abre no navegador)
  const link = `${APP_URL}/trampo-redefinir?token=${encodeURIComponent(token)}`;
  await enviarEmail(data.email, 'Redefinição de senha — Trampo', emailRecuperacaoSenha(data.nome, link));

  res.json(respostaGenerica);
});

app.post('/redefinir-senha', async (req, res) => {
  const { token, nova_senha } = req.body;
  if (!token || !nova_senha) return res.status(400).json({ erro: 'Token e nova senha obrigatórios.' });
  if (nova_senha.length < 6) return res.status(400).json({ erro: 'Mínimo 6 caracteres.' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.acao !== 'recuperar_senha') throw new Error();
    const tabela = payload.tipo === 'autonomo' ? 'autonomos' : 'usuarios';
    const senha_hash = await bcrypt.hash(nova_senha, 10);
    await supabase.from(tabela).update({ senha_hash }).eq('id', payload.id);
    res.json({ mensagem: 'Senha redefinida com sucesso!' });
  } catch { res.status(400).json({ erro: 'Token inválido ou expirado.' }); }
});

// ════════════════════════════════════════════════════════
//  CONVERTER PRÉ-CADASTRO
// ════════════════════════════════════════════════════════
app.get('/pre-cadastros/verificar/:email', async (req, res) => {
  const { data } = await supabase.from('pre_cadastros')
    .select('*').eq('email', req.params.email).eq('convertido', false).single();
  if (!data) return res.json({ encontrado: false });
  res.json({ encontrado: true, dados: data });
});

app.post('/pre-cadastros/converter/:id', async (req, res) => {
  const { autonomo_id } = req.body;
  if (!autonomo_id) return res.status(400).json({ erro: 'ID obrigatório.' });
  const { data: pre } = await supabase.from('pre_cadastros').select('*').eq('id', req.params.id).single();
  if (!pre) return res.status(404).json({ erro: 'Não encontrado.' });
  const update = {};
  if (pre.especialidade)  update.especialidade  = pre.especialidade;
  if (pre.bio)            update.bio            = pre.bio;
  if (pre.preco_medio)    update.preco_medio    = pre.preco_medio;
  if (pre.disponibilidade)update.disponibilidade= pre.disponibilidade;
  await supabase.from('autonomos').update(update).eq('id', autonomo_id);
  await supabase.from('pre_cadastros').update({ convertido: true }).eq('id', pre.id);
  res.json({ mensagem: 'Perfil importado!', dados: update });
});

// ════════════════════════════════════════════════════════
//  DENÚNCIAS
// ════════════════════════════════════════════════════════
app.post('/denuncias', autenticar, async (req, res) => {
  const { denunciado_id, denunciado_tipo, motivo, descricao } = req.body;
  if (!denunciado_id || !motivo) return res.status(400).json({ erro: 'Campos obrigatórios faltando.' });
  const { data, error } = await supabase.from('denuncias').insert([{
    denunciante_id:   req.usuario.id,
    denunciante_tipo: req.usuario.tipo,
    denunciado_id, denunciado_tipo, motivo, descricao,
  }]).select();
  if (error) return res.status(500).json({ erro: error.message });
  res.status(201).json({ mensagem: 'Denúncia registrada. Analisaremos em até 48h.', id: data[0].id });
});



// ════════════════════════════════════════════════════════
//  ASAAS — PAGAMENTOS
// ════════════════════════════════════════════════════════

// NOTA: a coluna 'pagarme_order_id' na tabela 'pedidos' é um nome legado;
// ela guarda o ID da cobrança no Asaas (não tem relação com Pagar.me).
// Mantida assim para não quebrar dados existentes no banco.
const ASAAS_URL = 'https://api.asaas.com/v3';
const ASAAS_KEY = process.env.ASAAS_API_KEY;
const TAXA_ASAAS_PIX = 1.98; // Taxa fixa por cobrança Pix (Pix + mensageria)

async function asaasReq(method, path, body) {
  const r = await fetch(`${ASAAS_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'access_token': ASAAS_KEY },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.errors?.[0]?.description || JSON.stringify(data));
  return data;
}

async function buscarOuCriarCliente(usuario) {
  const cpfLimpo = usuario.cpf ? usuario.cpf.replace(/[^0-9]/g, '') : '';
  
  try {
    const busca = await asaasReq('GET', `/customers?email=${encodeURIComponent(usuario.email)}`);
    if (busca.data?.length > 0) {
      const clienteExistente = busca.data[0];
      // SEMPRE atualizar CPF — garante que nunca vai faltar
      if (cpfLimpo) {
        await asaasReq('PUT', `/customers/${clienteExistente.id}`, {
          name: usuario.nome,
          cpfCnpj: cpfLimpo,
        }).catch(e => console.log('Erro ao atualizar CPF:', e.message));
      }
      return clienteExistente.id;
    }
  } catch {}

  const body = {
    name: usuario.nome, email: usuario.email,
    phone: (usuario.telefone || '').replace(/[^0-9]/g, ''),
    groupName: 'Trampo',
  };
  if (cpfLimpo) body.cpfCnpj = cpfLimpo;
  const c = await asaasReq('POST', '/customers', body);
  return c.id;
}

async function transferirAutonomo(pedido) {
  if (!pedido.autonomos?.chave_pix) {
    console.log('Autônomo sem chave Pix — transferência não realizada');
    return;
  }

  // ── TRAVA DE IDEMPOTÊNCIA ──
  // Marca transferido=true ANTES de transferir, mas só se ainda estiver false.
  // Como é uma operação condicional no banco, dois processos simultâneos não
  // conseguem ambos "ganhar" a trava — evita pagar o autônomo duas vezes.
  const { data: trava, error: travaErr } = await supabase
    .from('pedidos')
    .update({ transferido: true, transferido_em: new Date().toISOString() })
    .eq('id', pedido.id)
    .eq('transferido', false)   // só atualiza se ainda não foi transferido
    .select();

  if (travaErr) { console.log('Erro ao travar transferência:', travaErr.message); return; }
  if (!trava || trava.length === 0) {
    console.log(`Pedido ${pedido.id} já foi transferido (ou trava não pegou) — ignorando`);
    return; // outro processo já está cuidando / já foi pago
  }

  try {
    const valor = parseFloat((pedido.valor_servico * 0.9).toFixed(2));
    if (valor < 1) {
      console.log('Valor insuficiente para transferência');
      // libera a trava (não havia o que transferir)
      await supabase.from('pedidos').update({ transferido: false, transferido_em: null }).eq('id', pedido.id);
      return;
    }

    // Verificar se há saldo disponível na conta Asaas.
    // (No cartão o dinheiro pode levar até 2 dias úteis pra ficar disponível,
    //  mesmo com antecipação. Se não houver saldo, libera a trava e o retry
    //  a cada 2h tenta de novo quando o dinheiro cair.)
    try {
      const saldo = await asaasReq('GET', '/finance/balance');
      const disponivel = parseFloat(saldo?.balance ?? 0);
      if (disponivel < valor) {
        console.log(`Saldo insuficiente (R$${disponivel}) para transferir R$${valor} — pedido ${pedido.id}. Retry tentará depois.`);
        await supabase.from('pedidos').update({ transferido: false, transferido_em: null }).eq('id', pedido.id);
        return;
      }
    } catch (e) {
      // Se a checagem de saldo falhar, não bloqueia — segue e deixa o Asaas validar.
      console.log('Não foi possível checar saldo (seguindo mesmo assim):', e.message);
    }

    const chave = pedido.autonomos.chave_pix.trim();

    // Detectar tipo da chave Pix
    let pixAddressKeyType = 'EMAIL';
    const cpfRegex = /^[0-9]{11}$/;
    const cnpjRegex = /^[0-9]{14}$/;
    const telefoneRegex = /^[+]?[0-9]{10,13}$/;
    const chaveLimpa = chave.replace(/[^0-9]/g,'');

    if (cpfRegex.test(chaveLimpa)) pixAddressKeyType = 'CPF';
    else if (cnpjRegex.test(chaveLimpa)) pixAddressKeyType = 'CNPJ';
    else if (telefoneRegex.test(chave.replace(/[^0-9+]/g,''))) pixAddressKeyType = 'PHONE';
    else if (chave.includes('@')) pixAddressKeyType = 'EMAIL';
    else pixAddressKeyType = 'EVP'; // chave aleatória

    await asaasReq('POST', '/transfers', {
      value: valor,
      operationType: 'PIX',
      pixAddressKey: chave,
      pixAddressKeyType,
      description: `Trampo - Pagamento pedido ${pedido.id}`,
    });
    console.log(`Transferido R$${valor} para ${pedido.autonomos.nome} (${pixAddressKeyType})`);
    // Sucesso — a trava já marcou transferido=true, nada mais a fazer.
  } catch(e) {
    console.log('Erro transferência Asaas:', e.message);
    // FALHOU — reverter a trava pra permitir nova tentativa pelo retry
    await supabase.from('pedidos')
      .update({ transferido: false, transferido_em: null })
      .eq('id', pedido.id);
  }
}

app.post('/pagamentos/pix', autenticar, async (req, res) => {
  const { pedido_id } = req.body;
  if (!pedido_id) return res.status(400).json({ erro: 'pedido_id obrigatorio.' });
  const { cpf_temp } = req.body;
  const { data: pedido } = await supabase
    .from('pedidos').select('*, usuarios(*), servicos(*)')
    .eq('id', pedido_id).single();
  if (!pedido) return res.status(404).json({ erro: 'Pedido nao encontrado.' });

  try {
    const usuario = { ...pedido.usuarios, cpf: pedido.usuarios.cpf || cpf_temp };
    const clienteId = await buscarOuCriarCliente(usuario);
    const venc = new Date(Date.now() + 3600000).toISOString().split('T')[0];
    const cob = await asaasReq('POST', '/payments', {
      customer: clienteId, billingType: 'PIX',
      value: parseFloat(pedido.valor_total), dueDate: venc,
      description: pedido.servicos?.nome || 'Servico Trampo',
      externalReference: pedido_id,
    });
    const qr = await asaasReq('GET', `/payments/${cob.id}/pixQrCode`);
    await supabase.from('pedidos').update({ pagarme_order_id: cob.id, status: 'aguardando_pagamento' }).eq('id', pedido_id);
    res.json({ order_id: cob.id, pix_qrcode: qr.payload, pix_qrcode_url: cob.invoiceUrl, valor: pedido.valor_total });
  } catch(e) {
    console.error('Asaas PIX:', e.message);
    res.status(500).json({ erro: 'Erro ao criar cobrança Pix.', detalhes: e.message });
  }
});

app.post('/pagamentos/cartao', autenticar, async (req, res) => {
  const { pedido_id, card_number, card_holder_name, card_expiration_month,
          card_expiration_year, card_cvv, installments, valor_total } = req.body;
  if (!pedido_id || !card_number) return res.status(400).json({ erro: 'Dados incompletos.' });
  const { data: pedido } = await supabase.from('pedidos').select('*, usuarios(*)').eq('id', pedido_id).single();
  if (!pedido) return res.status(404).json({ erro: 'Pedido nao encontrado.' });

  try {
    const clienteId = await buscarOuCriarCliente(pedido.usuarios);
    const parc = parseInt(installments) || 1;
    const cob = await asaasReq('POST', '/payments', {
      customer: clienteId, billingType: 'CREDIT_CARD',
      value: parseFloat(valor_total), dueDate: new Date().toISOString().split('T')[0],
      description: 'Trampo - Servico', externalReference: pedido_id,
      installmentCount: parc,
      installmentValue: parseFloat((valor_total / parc).toFixed(2)),
      creditCard: {
        holderName: card_holder_name,
        number: card_number.replace(/\s/g, ''),
        expiryMonth: card_expiration_month,
        expiryYear: card_expiration_year,
        ccv: card_cvv,
      },
      creditCardHolderInfo: {
        name: pedido.usuarios.nome, email: pedido.usuarios.email,
        phone: (pedido.usuarios.telefone || '').replace(/[^0-9]/g, ''),
        postalCode: '90000000', addressNumber: '1',
      },
    });
    if (cob.status === 'CONFIRMED' || cob.status === 'RECEIVED') {
      await supabase.from('pedidos').update({ pagarme_order_id: cob.id, status: 'em_andamento', pago_em: new Date().toISOString() }).eq('id', pedido_id);
      return res.json({ status: 'approved', mensagem: 'Pagamento aprovado!' });
    }
    throw new Error('Pagamento recusado. Verifique os dados do cartao.');
  } catch(e) {
    console.error('Asaas Cartao:', e.message);
    res.status(500).json({ erro: e.message });
  }
});

app.post('/pagamentos/webhook', async (req, res) => {
  // Validação de autenticidade: o Asaas envia o token configurado no painel
  // no header 'asaas-access-token'. Configure ASAAS_WEBHOOK_TOKEN no Railway
  // com o mesmo valor cadastrado no Asaas (Configurações → Webhooks).
  const tokenRecebido = req.headers['asaas-access-token'];
  if (process.env.ASAAS_WEBHOOK_TOKEN && tokenRecebido !== process.env.ASAAS_WEBHOOK_TOKEN) {
    console.warn('[webhook] Token inválido — requisição rejeitada');
    return res.status(401).json({ erro: 'Não autorizado.' });
  }

  const { event, payment } = req.body;
  console.log('Webhook Asaas:', event, payment?.id);
  if (event === 'PAYMENT_RECEIVED' || event === 'PAYMENT_CONFIRMED') {
    const pedidoId = payment?.externalReference;
    if (pedidoId) {
      // Proteção contra webhook duplicado: gateways reenviam o mesmo evento.
      // Só processa se o pedido ainda não estiver em_andamento (evita push duplo).
      const { data: jaProcessado } = await supabase
        .from('pedidos').select('status').eq('id', pedidoId).single();
      if (jaProcessado?.status === 'em_andamento' || jaProcessado?.status === 'concluido') {
        console.log(`Webhook ignorado — pedido ${pedidoId} já está ${jaProcessado.status}`);
        return res.json({ ok: true, ja_processado: true });
      }

      await supabase.from('pedidos').update({ status: 'em_andamento', pago_em: new Date().toISOString() }).eq('id', pedidoId);

      // Notificar o autônomo que recebeu um pedido pago
      try {
        const { data: pedido } = await supabase
          .from('pedidos').select('*, autonomos(push_token, nome), servicos(nome)')
          .eq('id', pedidoId).single();
        if (pedido?.autonomos?.push_token) {
          enviarPush(
            pedido.autonomos.push_token,
            '🎉 Novo pedido pago!',
            `Você recebeu um pedido${pedido.servicos?.nome ? ' de ' + pedido.servicos.nome : ''}. Confira na agenda!`,
            { tipo: 'pedido', pedido_id: pedidoId }
          );
        }
      } catch {}
    }
  }
  res.json({ ok: true });
});

app.get('/pagamentos/status/:pedido_id', autenticar, async (req, res) => {
  if (!ehUUID(req.params.pedido_id)) return res.status(400).json({ erro: 'ID inválido.' });
  const { data: pedido } = await supabase.from('pedidos').select('status, pagarme_order_id, pago_em').eq('id', req.params.pedido_id).single();
  if (!pedido) return res.status(404).json({ erro: 'Pedido nao encontrado.' });
  if (pedido.pagarme_order_id && pedido.status === 'aguardando_pagamento') {
    try {
      const cob = await asaasReq('GET', `/payments/${pedido.pagarme_order_id}`);
      if (cob.status === 'RECEIVED' || cob.status === 'CONFIRMED') {
        await supabase.from('pedidos').update({ status: 'em_andamento', pago_em: new Date().toISOString() }).eq('id', req.params.pedido_id);
        return res.json({ status: 'em_andamento', pago_em: new Date().toISOString() });
      }
    } catch {}
  }
  res.json({ status: pedido.status, pago_em: pedido.pago_em });
});

//  ORCAMENTOS
// ════════════════════════════════════════════════════════

app.post('/orcamentos', autenticar, async (req, res) => {
  const { autonomo_id, descricao, categoria } = req.body;
  if (!autonomo_id || !descricao) return res.status(400).json({ erro: 'Campos obrigatorios faltando.' });
  const { data, error } = await supabase.from('orcamentos').insert([{
    usuario_id: req.usuario.id, autonomo_id, descricao, categoria,
    status: 'aguardando_resposta',
  }]).select();
  if (error) return res.status(500).json({ erro: error.message });

  // Notificar autônomo que recebeu pedido de orçamento
  try {
    const { data: auto } = await supabase.from('autonomos').select('push_token').eq('id', autonomo_id).single();
    if (auto?.push_token) {
      enviarPush(auto.push_token, '📋 Novo pedido de orçamento!',
        'Um cliente quer um orçamento seu. Responda agora!',
        { tipo: 'orcamento_pedido' });
    }
  } catch {}

  res.status(201).json({ orcamento: data[0] });
});

app.patch('/orcamentos/:id/responder', autenticar, async (req, res) => {
  const { valor, prazo, observacao } = req.body;
  if (!valor) return res.status(400).json({ erro: 'Valor obrigatorio.' });
  const { data, error } = await supabase.from('orcamentos')
    .update({ valor, prazo, observacao, status: 'respondido', respondido_em: new Date().toISOString() })
    .eq('id', req.params.id).eq('autonomo_id', req.usuario.id).select();
  if (error) return res.status(500).json({ erro: error.message });

  // Notificar cliente que recebeu orçamento
  try {
    const orc = data[0];
    const { data: cliente } = await supabase.from('usuarios').select('push_token').eq('id', orc.usuario_id).single();
    if (cliente?.push_token) {
      enviarPush(cliente.push_token, '💰 Orçamento recebido!',
        `Você recebeu um orçamento de R$ ${parseFloat(valor).toFixed(2)}. Confira no app!`,
        { tipo: 'orcamento', orcamento_id: orc.id });
    }
  } catch {}

  res.json({ orcamento: data[0] });
});

app.post('/orcamentos/:id/aprovar', autenticar, async (req, res) => {
  const { data: orc } = await supabase.from('orcamentos').select('*').eq('id', req.params.id).single();
  if (!orc) return res.status(404).json({ erro: 'Orcamento nao encontrado.' });
  if (orc.usuario_id !== req.usuario.id) return res.status(403).json({ erro: 'Sem permissao.' });
  const valor_servico   = orc.valor;
  const taxa_plataforma = parseFloat((valor_servico * 0.10).toFixed(2));
  const { data: pedido, error } = await supabase.from('pedidos').insert([{
    usuario_id: req.usuario.id, autonomo_id: orc.autonomo_id,
    descricao: orc.descricao, valor_servico, taxa_plataforma,
    valor_total: valor_servico, status: 'aguardando_pagamento',
  }]).select();
  if (error) return res.status(500).json({ erro: error.message });
  await supabase.from('orcamentos').update({ status: 'aprovado', pedido_id: pedido[0].id }).eq('id', orc.id);
  res.status(201).json({ pedido: pedido[0] });
});

app.get('/orcamentos', autenticar, async (req, res) => {
  const campo = req.usuario.tipo === 'autonomo' ? 'autonomo_id' : 'usuario_id';
  const { data, error } = await supabase.from('orcamentos')
    .select('*, usuarios(nome), autonomos(nome, especialidade)')
    .eq(campo, req.usuario.id)
    .order('criado_em', { ascending: false });
  if (error) return res.status(500).json({ erro: error.message });
  res.json(data);
});


app.patch('/pedidos/:id/cancelar', autenticar, async (req, res) => {
  const { data: pedido } = await supabase
    .from('pedidos').select('*').eq('id', req.params.id).single();
  if (!pedido) return res.status(404).json({ erro: 'Pedido não encontrado.' });
  if (pedido.usuario_id !== req.usuario.id) return res.status(403).json({ erro: 'Sem permissão.' });
  if (!['aguardando_pagamento'].includes(pedido.status))
    return res.status(400).json({ erro: 'Só é possível cancelar pedidos aguardando pagamento.' });
  const { error } = await supabase.from('pedidos')
    .update({ status: 'cancelado' }).eq('id', req.params.id);
  if (error) return res.status(500).json({ erro: error.message });
  res.json({ mensagem: 'Pedido cancelado.' });
});


app.get('/avaliacoes/minhas', autenticar, async (req, res) => {
  const { data, error } = await supabase
    .from('avaliacoes')
    .select('nota, comentario, criado_em, usuarios(nome)')
    .eq('autonomo_id', req.usuario.id)
    .order('criado_em', { ascending: false });
  if (error) return res.status(500).json({ erro: error.message });
  res.json(data);
});


app.patch('/orcamentos/:id/recusar', autenticar, async (req, res) => {
  const { data, error } = await supabase.from('orcamentos')
    .update({ status: 'recusado' })
    .eq('id', req.params.id)
    .eq('usuario_id', req.usuario.id)
    .select();
  if (error) return res.status(500).json({ erro: error.message });
  res.json({ orcamento: data[0] });
});


// ════════════════════════════════════════════════════════
//  LIBERAÇÃO AUTOMÁTICA — roda a cada hora
// ════════════════════════════════════════════════════════
async function verificarLiberacaoAutomatica() {
  try {
    const limite = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
    // Liberar apenas pedidos em andamento, pagos há +48h, E QUE NÃO ESTÃO EM DISPUTA
    const { data: pedidos } = await supabase
      .from('pedidos')
      .select('*, autonomos(chave_pix, nome)')
      .eq('status', 'em_andamento')
      .lt('pago_em', limite);

    for (const pedido of pedidos || []) {
      // Segurança extra: pular se houver disputa registrada
      if (pedido.disputa_em || pedido.status === 'em_disputa') {
        console.log(`Pedido ${pedido.id} tem disputa — liberação automática pausada`);
        continue;
      }

      console.log(`Liberando automaticamente pedido ${pedido.id} — 48h sem confirmação nem disputa`);
      await supabase.from('pedidos')
        .update({
          status: 'concluido',
          concluido_em: new Date().toISOString(),
          liberado_automaticamente: true,
          transferido: false
        })
        .eq('id', pedido.id);

      // Transferir pro autônomo via Asaas
      if (pedido.autonomos?.chave_pix) {
        await transferirAutonomo({ ...pedido, autonomos: pedido.autonomos });
      }
    }
  } catch(e) {
    console.error('Erro liberação automática:', e.message);
  }
}

// Rodar a cada hora
setInterval(verificarLiberacaoAutomatica, 60 * 60 * 1000);

// 2. Rota de disputa — cliente OU autônomo abre, com foto + descrição obrigatórias
app.post('/pedidos/:id/disputa', autenticar, async (req, res) => {
  const { motivo, foto_url } = req.body;
  const { data: pedido } = await supabase
    .from('pedidos').select('*').eq('id', req.params.id).single();

  if (!pedido) return res.status(404).json({ erro: 'Pedido não encontrado.' });

  // Cliente OU autônomo do pedido podem abrir disputa
  const ehCliente = pedido.usuario_id === req.usuario.id;
  const ehAutonomo = pedido.autonomo_id === req.usuario.id;
  if (!ehCliente && !ehAutonomo) return res.status(403).json({ erro: 'Sem permissão.' });

  // Só em pedidos pagos / em andamento (precisa ter dinheiro retido pra disputar)
  if (pedido.status !== 'em_andamento') {
    return res.status(400).json({ erro: 'Só é possível abrir disputa em pedidos pagos e em andamento.' });
  }

  // Descrição obrigatória (mínimo 10 caracteres)
  if (!motivo || motivo.trim().length < 10) {
    return res.status(400).json({ erro: 'Descreva o problema com pelo menos 10 caracteres.' });
  }

  await supabase.from('pedidos').update({
    status: 'em_disputa',
    disputa_motivo: motivo.trim(),
    disputa_foto: foto_url || null,
    disputa_aberta_por: ehCliente ? 'cliente' : 'autonomo',
    disputa_em: new Date().toISOString()
  }).eq('id', req.params.id);

  res.json({ mensagem: 'Disputa aberta! Nossa equipe vai analisar e entrar em contato em até 24h pelo Instagram @trampoapp_.' });
});

// Listar disputas (para painel admin)
app.get('/admin/disputas', async (req, res) => {
  // Aceita senha via header (preferido, não fica em logs de URL) ou query (fallback)
  const senha = req.headers['x-admin-secret'] || req.query.senha;
  if (senha !== process.env.ADMIN_SECRET) return res.status(403).json({ erro: 'Sem permissão.' });

  const { data } = await supabase
    .from('pedidos')
    .select('*, usuarios(nome, email, telefone), autonomos(nome, email, telefone, chave_pix), servicos(nome)')
    .eq('status', 'em_disputa')
    .order('disputa_em', { ascending: true });

  res.json({ disputas: data || [] });
});

// Resolver disputa — estornar / liberar / dividir
app.post('/admin/disputas/:id/resolver', async (req, res) => {
  const { senha, decisao, percentual_autonomo } = req.body;
  if (senha !== process.env.ADMIN_SECRET) return res.status(403).json({ erro: 'Sem permissão.' });

  const { data: pedido } = await supabase
    .from('pedidos').select('*, autonomos(chave_pix, nome)').eq('id', req.params.id).single();
  if (!pedido) return res.status(404).json({ erro: 'Pedido não encontrado.' });
  if (pedido.status !== 'em_disputa') return res.status(400).json({ erro: 'Pedido não está em disputa.' });

  // decisao: 'estornar' (devolve cliente) | 'liberar' (paga autônomo 90%) | 'dividir' (paga % ao autônomo)
  if (decisao === 'estornar') {
    // Estornar cobrança no Asaas (volta pra origem)
    try {
      if (pedido.pagarme_order_id) {
        await asaasReq('POST', `/payments/${pedido.pagarme_order_id}/refund`, {});
      }
    } catch(e) { console.log('Erro estorno:', e.message); }

    await supabase.from('pedidos').update({
      status: 'cancelado',
      disputa_resolucao: 'estornado',
      disputa_resolvido_em: new Date().toISOString()
    }).eq('id', req.params.id);

    return res.json({ mensagem: 'Disputa resolvida: valor estornado ao cliente.' });
  }

  if (decisao === 'liberar') {
    await supabase.from('pedidos').update({
      status: 'concluido',
      concluido_em: new Date().toISOString(),
      disputa_resolucao: 'liberado_autonomo',
      disputa_resolvido_em: new Date().toISOString(),
      transferido: false
    }).eq('id', req.params.id);

    if (pedido.autonomos?.chave_pix) {
      await transferirAutonomo({ ...pedido, autonomos: pedido.autonomos });
    }
    return res.json({ mensagem: 'Disputa resolvida: pagamento liberado ao autônomo.' });
  }

  if (decisao === 'dividir') {
    const pct = parseFloat(percentual_autonomo) || 50;
    const valorAutonomo = parseFloat((pedido.valor_servico * (pct/100)).toFixed(2));

    // Transferir parte ao autônomo (transferirAutonomo cuida da trava transferido)
    if (pedido.autonomos?.chave_pix && valorAutonomo >= 1) {
      await transferirAutonomo({
        ...pedido,
        autonomos: pedido.autonomos,
        // transferirAutonomo multiplica por 0.9; o /0.9 aqui cancela isso,
        // resultando em transferir exatamente (valor * pct/100) ao autônomo
        valor_servico: pedido.valor_servico * (pct/100) / 0.9
      });
    }

    await supabase.from('pedidos').update({
      status: 'concluido',
      concluido_em: new Date().toISOString(),
      disputa_resolucao: `dividido_${pct}`,
      disputa_resolvido_em: new Date().toISOString()
      // 'transferido' é controlado pela própria transferirAutonomo (trava de idempotência)
    }).eq('id', req.params.id);

    return res.json({ mensagem: `Disputa resolvida: ${pct}% liberado ao autônomo (R$ ${valorAutonomo.toFixed(2)}).` });
  }

  res.status(400).json({ erro: 'Decisão inválida. Use: estornar, liberar ou dividir.' });
});

// 3. Admin libera pagamento (você mesmo via API)
app.post('/admin/liberar/:pedido_id', async (req, res) => {
  const { senha } = req.body;
  if (senha !== process.env.ADMIN_SECRET) return res.status(403).json({ erro: 'Sem permissão.' });

  const { data: pedido } = await supabase
    .from('pedidos').select('*, autonomos(chave_pix, nome)').eq('id', req.params.pedido_id).single();
  if (!pedido) return res.status(404).json({ erro: 'Pedido não encontrado.' });

  await supabase.from('pedidos').update({
    status: 'concluido',
    concluido_em: new Date().toISOString(),
    liberado_admin: true,
    transferido: false
  }).eq('id', req.params.pedido_id);

  // Transferir ao autônomo (transferirAutonomo cuida da trava de idempotência)
  if (pedido.autonomos?.chave_pix) {
    await transferirAutonomo({ ...pedido, autonomos: pedido.autonomos, transferido: false });
  }

  res.json({ mensagem: `Pedido ${req.params.pedido_id} liberado pelo admin e pagamento transferido ao autônomo.` });
});


app.patch('/usuarios/atualizar-cpf', autenticar, async (req, res) => {
  const { cpf } = req.body;
  if (!cpf) return res.status(400).json({ erro: 'CPF obrigatorio.' });
  await supabase.from('usuarios').update({ cpf }).eq('id', req.usuario.id);
  res.json({ mensagem: 'CPF atualizado!' });
});


app.put('/usuarios/perfil', autenticar, async (req, res) => {
  const { nome, telefone, cpf } = req.body;
  const dados = { nome, telefone };
  if (cpf !== undefined) dados.cpf = cpf;
  const { error } = await supabase.from('usuarios')
    .update(dados)
    .eq('id', req.usuario.id);
  if (error) return res.status(500).json({ erro: error.message });
  res.json({ mensagem: 'Perfil atualizado!' });
});


// ════════════════════════════════════════════════════════
//  EXCLUSÃO DE CONTA (LGPD / Google Play)
//  Anonimiza os dados pessoais imediatamente (em vez de
//  deletar a linha, o que quebraria pedidos vinculados que
//  precisam ser mantidos por obrigação fiscal) e remove
//  mensagens. Funciona para cliente e autônomo.
// ════════════════════════════════════════════════════════

app.delete('/conta', autenticar, async (req, res) => {
  const id = req.usuario.id;
  const ehAutonomo = req.usuario.tipo === 'autonomo';
  const tabela = ehAutonomo ? 'autonomos' : 'usuarios';

  try {
    // 1. Apagar mensagens enviadas e recebidas
    const { error: errMsg } = await supabase.from('mensagens').delete().or(`de_id.eq.${id},para_id.eq.${id}`);
    if (errMsg) console.error('[excluir conta] erro ao apagar mensagens:', errMsg.message);

    // 2. Autônomo: apagar os serviços oferecidos
    if (ehAutonomo) {
      const { error: errServ } = await supabase.from('servicos').delete().eq('autonomo_id', id);
      if (errServ) console.error('[excluir conta] erro ao apagar serviços:', errServ.message);
    }

    // 3. Anonimizar dados pessoais (LGPD)
    const dadosAnonimos = {
      nome: 'Conta excluída',
      email: `excluido_${id}@trampo.invalid`,
      senha_hash: 'CONTA_EXCLUIDA',
      telefone: null,
      push_token: null,
    };
    if (ehAutonomo) {
      Object.assign(dadosAnonimos, { chave_pix: null, bio: null, ativo: false });
    }

    let { error } = await supabase.from(tabela).update(dadosAnonimos).eq('id', id);

    // Se falhou por causa de alguma coluna que não existe (ex: cpf), tenta de novo
    // sem os campos opcionais — garante que a anonimização principal aconteça.
    if (error) {
      console.error('[excluir conta] erro no update, tentando versão mínima:', error.message);
      const minimo = {
        nome: 'Conta excluída',
        email: `excluido_${id}@trampo.invalid`,
        senha_hash: 'CONTA_EXCLUIDA',
      };
      const retry = await supabase.from(tabela).update(minimo).eq('id', id);
      if (retry.error) {
        console.error('[excluir conta] erro mesmo no mínimo:', retry.error.message);
        return res.status(500).json({ erro: 'Erro ao excluir conta: ' + retry.error.message });
      }
    }

    res.json({ mensagem: 'Conta excluída com sucesso.' });
  } catch (e) {
    console.error('[excluir conta] exceção:', e.message);
    res.status(500).json({ erro: 'Erro ao excluir conta: ' + e.message });
  }
});


// ════════════════════════════════════════════════════════
//  RETRY DE TRANSFERÊNCIAS PENDENTES
// ════════════════════════════════════════════════════════

async function tentarTransferenciaPendente(pedidoId) {
  const { data: pedido } = await supabase
    .from('pedidos')
    .select('*, autonomos(chave_pix, nome)')
    .eq('id', pedidoId)
    .single();
  
  if (!pedido || pedido.transferido) return;
  
  try {
    await transferirAutonomo(pedido);
    // Marcar como transferido
    await supabase.from('pedidos')
      .update({ transferido: true, transferido_em: new Date().toISOString() })
      .eq('id', pedidoId);
    console.log(`Transferência concluída para pedido ${pedidoId}`);
  } catch(e) {
    console.log(`Retry falhou para pedido ${pedidoId}:`, e.message);
  }
}

// Rodar retry a cada 2 horas
setInterval(async () => {
  const { data: pendentes } = await supabase
    .from('pedidos')
    .select('id')
    .eq('status', 'concluido')
    .eq('transferido', false);
  
  for (const p of pendentes || []) {
    await tentarTransferenciaPendente(p.id);
    await new Promise(r => setTimeout(r, 2000)); // espera 2s entre cada
  }
}, 2 * 60 * 60 * 1000);


// ════════════════════════════════════════════════════════
//  NOTIFICAÇÕES PUSH (via Expo)
// ════════════════════════════════════════════════════════

async function enviarPush(pushToken, titulo, corpo, dados = {}) {
  if (!pushToken || !pushToken.startsWith('ExponentPushToken')) return;
  try {
    await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        to: pushToken,
        sound: 'default',
        title: titulo,
        body: corpo,
        data: dados,
        priority: 'high',
      }),
    });
    console.log(`Push enviado: ${titulo}`);
  } catch(e) {
    console.log('Erro ao enviar push:', e.message);
  }
}

// Salvar push token do usuário/autônomo
app.post('/push-token', autenticar, async (req, res) => {
  const { push_token } = req.body;
  if (!push_token) return res.status(400).json({ erro: 'push_token obrigatorio.' });

  // Atualizar na tabela correta conforme o tipo do usuário
  const tabela = req.usuario.tipo === 'autonomo' ? 'autonomos' : 'usuarios';
  await supabase.from(tabela).update({ push_token }).eq('id', req.usuario.id);

  res.json({ mensagem: 'Token salvo!' });
});

// ── Health check ──────────────────────────────────────────
app.get('/ping', (req, res) => res.json({ status: 'ok', app: 'Trampo API', versao: '1.0.0' }));

// Keep-alive: faz uma consulta leve no Supabase para evitar que o projeto
// pause por inatividade (plano grátis pausa após 7 dias sem atividade).
// Configure um monitor externo (UptimeRobot/cron-job.org) chamando esta rota
// 1x por dia. PALIATIVO para a fase de testes — em produção, use o plano Pro.
app.get('/keep-alive', async (req, res) => {
  try {
    // Consulta mínima (conta 1 registro) só pra registrar atividade no banco
    await supabase.from('autonomos').select('id', { count: 'exact', head: true }).limit(1);
    res.json({ status: 'ok', banco: 'ativo', em: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ status: 'erro', erro: e.message });
  }
});

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🟢 Trampo API rodando em http://localhost:${PORT}`);
  console.log(`   Teste: http://localhost:${PORT}/ping\n`);
});
