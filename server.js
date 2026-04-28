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
  const { nome, email, telefone, bairro, categoria,
          especialidade, preco_medio, disponibilidade,
          bio, como_soube } = req.body;

  if (!nome || !telefone || !bairro || !categoria) {
    return res.status(400).json({ erro: 'Campos obrigatórios faltando.' });
  }

  const { data, error } = await supabase
    .from('pre_cadastros')
    .insert([{ nome, email, telefone, bairro, categoria,
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
  const campos = ['telefone','bairro','bio','preco_medio','disponibilidade','ativo'];
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
  const { autonomo_id, servico_id, descricao, data_agendada } = req.body;
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
    data_agendada: data_agendada || null,
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
    .update({ status: 'concluido', concluido_em: new Date().toISOString() })
    .eq('id', req.params.id).select();

  // Incrementa contador de serviços do autônomo
  await supabase.rpc('incrementar_servicos', { autonomo_id: pedido.autonomo_id });

  if (error) return res.status(500).json({ erro: error.message });
  res.json({ mensagem: 'Serviço concluído! Pagamento liberado.', pedido: data[0] });
});

// ── Listar pedidos do usuário ─────────────────────────────
app.get('/pedidos', autenticar, async (req, res) => {
  const campo = req.usuario.tipo === 'autonomo' ? 'autonomo_id' : 'usuario_id';
  const { data, error } = await supabase
    .from('pedidos')
    .select('*, servicos(nome), autonomos(nome), usuarios(nome)')
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
app.post('/push-token', autenticar, async (req, res) => {
  const { push_token } = req.body;
  if (!push_token) return res.status(400).json({ erro: 'Token obrigatório.' });
  const tabela = req.usuario.tipo === 'autonomo' ? 'autonomos' : 'usuarios';
  await supabase.from(tabela).update({ push_token }).eq('id', req.usuario.id);
  res.json({ mensagem: 'Token salvo!' });
});
// ── Health check ──────────────────────────────────────────
app.get('/ping', (req, res) => res.json({ status: 'ok', app: 'Trampo API', versao: '1.0.0' }));

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🟢 Trampo API rodando em http://localhost:${PORT}`);
  console.log(`   Teste: http://localhost:${PORT}/ping\n`);
});
