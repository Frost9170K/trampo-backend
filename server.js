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
          disponibilidade, lat, lng } = req.body;

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
               disponibilidade, lat, lng, localizacao }])
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
  const { categoria, lat, lng, raio = 10, busca } = req.query;

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
    .select('id, nome, categoria, especialidade, bairro, nota_media, total_avaliacoes, verificado, preco_medio')
    .eq('ativo', true)
    .order('nota_media', { ascending: false });

  if (categoria) query = query.eq('categoria', categoria);
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
      verificado, disponibilidade, preco_medio,
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

// ── Atualizar perfil do autônomo ──────────────────────────
app.put('/autonomos/painel/perfil', autenticar, async (req, res) => {
  const campos = ['telefone','bairro','bio','preco_medio','disponibilidade','ativo','especialidade','chave_pix'];
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
  const { nome, email, senha, telefone } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Campos obrigatórios faltando.' });

  const { data: existe } = await supabase
    .from('usuarios').select('id').eq('email', email).single();
  if (existe) return res.status(409).json({ erro: 'Email já cadastrado.' });

  const senha_hash = await bcrypt.hash(senha, 10);
  const { data, error } = await supabase
    .from('usuarios').insert([{ nome, email, senha_hash, telefone }]).select('id, nome, email');

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
  const { autonomo_id, servico_id, descricao, data_agendada, observacao, metodo_pagamento, data_agendamento, hora_agendamento } = req.body;
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

  const { data, error } = await supabase
    .from('pedidos')
    .update({ status: 'concluido', concluido_em: new Date().toISOString(), transferido: false })
    .eq('id', req.params.id).select();

  // Incrementa contador de serviços do autônomo
  await supabase.rpc('incrementar_servicos', { autonomo_id: pedido.autonomo_id });

  if (error) return res.status(500).json({ erro: error.message });

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
    .select('*, servicos(nome), autonomos(nome, especialidade, categoria), usuarios(nome), avaliacoes(nota, comentario)')
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
  res.status(201).json({ mensagem: data[0] });
});

app.get('/mensagens/:outro_id', autenticar, async (req, res) => {
  const meuId   = req.usuario.id;
  const outroId = req.params.outro_id;

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

app.get('/conversas', autenticar, async (req, res) => {
  const meuId = req.usuario.id;
  const { data, error } = await supabase
    .from('mensagens')
    .select('*')
    .or(`de_id.eq.${meuId},para_id.eq.${meuId}`)
    .order('criado_em', { ascending: false });

  if (error) return res.status(500).json({ erro: error.message });

  const conversas = {};
  (data || []).forEach(m => {
    const outroId = m.de_id === meuId ? m.para_id : m.de_id;
    if (!conversas[outroId]) conversas[outroId] = m;
  });

  res.json(Object.values(conversas));
});

app.get('/mensagens/nao-lidas/count', autenticar, async (req, res) => {
  const { count } = await supabase
    .from('mensagens')
    .select('*', { count: 'exact', head: true })
    .eq('para_id', req.usuario.id)
    .eq('lida', false);
  res.json({ total: count || 0 });
});


// ════════════════════════════════════════════════════════
//  RECUPERAÇÃO DE SENHA
// ════════════════════════════════════════════════════════
app.post('/recuperar-senha', async (req, res) => {
  const { email, tipo } = req.body;
  if (!email) return res.status(400).json({ erro: 'Email obrigatório.' });
  const tabela = tipo === 'autonomo' ? 'autonomos' : 'usuarios';
  const { data } = await supabase.from(tabela).select('id, nome, email').eq('email', email).single();
  if (!data) return res.json({ mensagem: 'Se o email existir, você receberá as instruções.' });
  const token = jwt.sign(
    { id: data.id, tipo: tipo||'usuario', acao: 'recuperar_senha' },
    process.env.JWT_SECRET, { expiresIn: '1h' }
  );
  res.json({ mensagem: 'Instruções enviadas!', token_dev: token });
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
  try {
    const valor = parseFloat((pedido.valor_servico * 0.9).toFixed(2));
    if (valor < 1) { console.log('Valor insuficiente para transferência'); return; }
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
    console.log(`Transferido R$${valor} para ${pedido.autonomos.nome} (${pixAddressKeyType}: ${chave})`)
    // Marcar como transferido no banco
    await supabase.from('pedidos')
      .update({ transferido: true, transferido_em: new Date().toISOString() })
      .eq('id', pedido.id)
      .catch(()=>{});;
  } catch(e) {
    console.log('Erro transferência Asaas:', e.message);
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
  const { event, payment } = req.body;
  console.log('Webhook Asaas:', event, payment?.id);
  if (event === 'PAYMENT_RECEIVED' || event === 'PAYMENT_CONFIRMED') {
    const pedidoId = payment?.externalReference;
    if (pedidoId) {
      await supabase.from('pedidos').update({ status: 'em_andamento', pago_em: new Date().toISOString() }).eq('id', pedidoId);
    }
  }
  res.json({ ok: true });
});

app.get('/pagamentos/status/:pedido_id', autenticar, async (req, res) => {
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
  res.status(201).json({ orcamento: data[0] });
});

app.patch('/orcamentos/:id/responder', autenticar, async (req, res) => {
  const { valor, prazo, observacao } = req.body;
  if (!valor) return res.status(400).json({ erro: 'Valor obrigatorio.' });
  const { data, error } = await supabase.from('orcamentos')
    .update({ valor, prazo, observacao, status: 'respondido', respondido_em: new Date().toISOString() })
    .eq('id', req.params.id).eq('autonomo_id', req.usuario.id).select();
  if (error) return res.status(500).json({ erro: error.message });
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


app.post('/pagamentos/cartao', autenticar, async (req, res) => {
  const { pedido_id, card_number, card_holder_name, card_expiration_month,
          card_expiration_year, card_cvv, installments, valor_total } = req.body;

  if (!pedido_id || !card_number) return res.status(400).json({ erro: 'Dados incompletos.' });

  const { data: pedido } = await supabase
    .from('pedidos').select('*, usuarios(*)').eq('id', pedido_id).single();
  if (!pedido) return res.status(404).json({ erro: 'Pedido não encontrado.' });

  try {
    // 1. Tokenizar o cartão
    const tokenRes = await fetch('https://api.mercadopago.com/v1/card_tokens', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
      },
      body: JSON.stringify({
        card_number, card_holder_name,
        card_expiration_month, card_expiration_year,
        security_code: card_cvv,
        cardholder: { name: card_holder_name },
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokenData.message || 'Erro ao tokenizar cartão.');

    // 2. Criar pagamento
    const pagRes = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
        'X-Idempotency-Key': `cartao-${pedido_id}-${Date.now()}`,
      },
      body: JSON.stringify({
        transaction_amount: parseFloat(valor_total),
        token: tokenData.id,
        description: 'Serviço Trampo',
        installments: parseInt(installments) || 1,
        payment_method_id: 'visa', // MP detecta automaticamente
        payer: {
          email: pedido.usuarios.email,
          first_name: pedido.usuarios.nome?.split(' ')[0] || 'Cliente',
          last_name: pedido.usuarios.nome?.split(' ').slice(1).join(' ') || 'Trampo',
        },
        notification_url: `${process.env.API_URL || 'https://web-production-8a9e5.up.railway.app'}/pagamentos/webhook`,
        metadata: { pedido_id },
      })
    });

    const pagData = await pagRes.json();
    if (!pagRes.ok) throw new Error(pagData.message || 'Erro ao processar pagamento.');

    if (pagData.status === 'approved') {
      await supabase.from('pedidos').update({
        pagarme_order_id: String(pagData.id),
        status: 'em_andamento',
        pago_em: new Date().toISOString()
      }).eq('id', pedido_id);
      return res.json({ status: 'approved', mensagem: 'Pagamento aprovado!' });
    }

    if (pagData.status === 'in_process' || pagData.status === 'pending') {
      await supabase.from('pedidos').update({
        pagarme_order_id: String(pagData.id),
        status: 'aguardando_pagamento',
      }).eq('id', pedido_id);
      return res.json({ status: 'pending', mensagem: 'Pagamento em análise.' });
    }

    throw new Error(pagData.status_detail || 'Pagamento recusado. Verifique os dados do cartão.');

  } catch(e) {
    console.error('Erro cartão:', e.message);
    res.status(500).json({ erro: e.message });
  }
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
    const { data: pedidos } = await supabase
      .from('pedidos')
      .select('*, autonomos(chave_pix, nome)')
      .eq('status', 'em_andamento')
      .lt('pago_em', limite);

    for (const pedido of pedidos || []) {
      console.log(`Liberando automaticamente pedido ${pedido.id} — 48h sem confirmação`);
      await supabase.from('pedidos')
        .update({ status: 'concluido', concluido_em: new Date().toISOString(), liberado_automaticamente: true })
        .eq('id', pedido.id);

      // Transferir pro autônomo
      if (pedido.autonomos?.chave_pix && process.env.MP_ACCESS_TOKEN) {
        const valorAutonomo = parseFloat((pedido.valor_servico * 0.9).toFixed(2));
        await fetch('https://api.mercadopago.com/v1/payments', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
            'X-Idempotency-Key': `auto-${pedido.id}`,
          },
          body: JSON.stringify({
            transaction_amount: valorAutonomo,
            description: `Trampo - Pagamento automático #${pedido.id}`,
            payment_method_id: 'pix',
            payer: { email: 'pagamento@trampo.app' },
            point_of_interaction: { linked_to: pedido.autonomos.chave_pix }
          })
        }).catch(e => console.log('Erro transferência auto:', e.message));
      }
    }
  } catch(e) {
    console.error('Erro liberação automática:', e.message);
  }
}

// Rodar a cada hora
setInterval(verificarLiberacaoAutomatica, 60 * 60 * 1000);

// 2. Rota de disputa — autônomo abre disputa se cliente não confirmar
app.post('/pedidos/:id/disputa', autenticar, async (req, res) => {
  const { motivo } = req.body;
  const { data: pedido } = await supabase
    .from('pedidos').select('*').eq('id', req.params.id).single();

  if (!pedido) return res.status(404).json({ erro: 'Pedido não encontrado.' });
  if (pedido.autonomo_id !== req.usuario.id) return res.status(403).json({ erro: 'Sem permissão.' });
  if (pedido.status !== 'em_andamento') return res.status(400).json({ erro: 'Só é possível abrir disputa em pedidos em andamento.' });

  await supabase.from('pedidos').update({
    status: 'em_disputa',
    disputa_motivo: motivo || 'Serviço concluído sem confirmação do cliente.',
    disputa_em: new Date().toISOString()
  }).eq('id', req.params.id);

  res.json({ mensagem: 'Disputa aberta. Analisaremos em até 24h.' });
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
    liberado_admin: true
  }).eq('id', req.params.pedido_id);

  res.json({ mensagem: `Pedido ${req.params.pedido_id} liberado pelo admin.` });
});


app.patch('/usuarios/atualizar-cpf', autenticar, async (req, res) => {
  const { cpf } = req.body;
  if (!cpf) return res.status(400).json({ erro: 'CPF obrigatorio.' });
  await supabase.from('usuarios').update({ cpf }).eq('id', req.usuario.id);
  res.json({ mensagem: 'CPF atualizado!' });
});


app.put('/usuarios/perfil', autenticar, async (req, res) => {
  const { nome, telefone } = req.body;
  const { error } = await supabase.from('usuarios')
    .update({ nome, telefone })
    .eq('id', req.usuario.id);
  if (error) return res.status(500).json({ erro: error.message });
  res.json({ mensagem: 'Perfil atualizado!' });
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

// ── Health check ──────────────────────────────────────────
app.get('/ping', (req, res) => res.json({ status: 'ok', app: 'Trampo API', versao: '1.0.0' }));

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🟢 Trampo API rodando em http://localhost:${PORT}`);
  console.log(`   Teste: http://localhost:${PORT}/ping\n`);
});
