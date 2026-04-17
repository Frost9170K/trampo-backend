-- ══════════════════════════════════════════
--  TRAMPO — Banco de dados (Supabase / PostgreSQL)
--  Cole este SQL no editor do Supabase e execute
-- ══════════════════════════════════════════

-- Extensão para busca geográfica por distância
create extension if not exists postgis;

-- ──────────────────────────────────────────
--  USUÁRIOS (clientes)
-- ──────────────────────────────────────────
create table usuarios (
  id          uuid primary key default gen_random_uuid(),
  nome        text not null,
  email       text unique not null,
  senha_hash  text not null,
  telefone    text,
  cidade      text default 'Porto Alegre',
  criado_em   timestamp default now()
);

-- ──────────────────────────────────────────
--  AUTONOMOS
-- ──────────────────────────────────────────
create table autonomos (
  id              uuid primary key default gen_random_uuid(),
  nome            text not null,
  email           text unique not null,
  senha_hash      text not null,
  telefone        text not null,
  bairro          text not null,
  cidade          text default 'Porto Alegre',
  categoria       text not null,
  especialidade   text,
  bio             text,
  preco_medio     text,
  disponibilidade text,
  nota_media      numeric(3,1) default 0,
  total_avaliacoes int default 0,
  total_servicos  int default 0,
  verificado      boolean default false,
  ativo           boolean default true,
  lat             double precision,
  lng             double precision,
  localizacao     geography(Point, 4326),
  como_soube      text,
  criado_em       timestamp default now()
);

-- ──────────────────────────────────────────
--  PRÉ-CADASTROS (do formulário de divulgação)
-- ──────────────────────────────────────────
create table pre_cadastros (
  id              uuid primary key default gen_random_uuid(),
  nome            text not null,
  email           text,
  telefone        text not null,
  bairro          text not null,
  categoria       text not null,
  especialidade   text,
  preco_medio     text,
  disponibilidade text,
  bio             text,
  como_soube      text,
  convertido      boolean default false,
  criado_em       timestamp default now()
);

-- ──────────────────────────────────────────
--  SERVIÇOS (catálogo do autônomo)
-- ──────────────────────────────────────────
create table servicos (
  id           uuid primary key default gen_random_uuid(),
  autonomo_id  uuid references autonomos(id) on delete cascade,
  nome         text not null,
  descricao    text,
  preco        numeric(10,2) not null,
  unidade      text default 'serviço',
  ativo        boolean default true,
  criado_em    timestamp default now()
);

-- ──────────────────────────────────────────
--  PEDIDOS / CONTRATAÇÕES
-- ──────────────────────────────────────────
create type status_pedido as enum (
  'aguardando_pagamento',
  'pago',
  'em_andamento',
  'concluido',
  'cancelado',
  'disputado'
);

create table pedidos (
  id              uuid primary key default gen_random_uuid(),
  usuario_id      uuid references usuarios(id),
  autonomo_id     uuid references autonomos(id),
  servico_id      uuid references servicos(id),
  status          status_pedido default 'aguardando_pagamento',
  valor_servico   numeric(10,2) not null,
  taxa_plataforma numeric(10,2) not null,
  valor_total     numeric(10,2) not null,
  descricao       text,
  data_agendada   timestamp,
  pago_em         timestamp,
  concluido_em    timestamp,
  cancelado_em    timestamp,
  criado_em       timestamp default now()
);

-- ──────────────────────────────────────────
--  AVALIAÇÕES
-- ──────────────────────────────────────────
create table avaliacoes (
  id           uuid primary key default gen_random_uuid(),
  pedido_id    uuid references pedidos(id),
  usuario_id   uuid references usuarios(id),
  autonomo_id  uuid references autonomos(id),
  nota         int check (nota between 1 and 5),
  comentario   text,
  criado_em    timestamp default now(),
  unique(pedido_id)
);

-- ──────────────────────────────────────────
--  FUNÇÃO: atualiza nota média do autônomo
-- ──────────────────────────────────────────
create or replace function atualizar_nota_autonomo()
returns trigger as $$
begin
  update autonomos set
    nota_media       = (select round(avg(nota)::numeric, 1) from avaliacoes where autonomo_id = NEW.autonomo_id),
    total_avaliacoes = (select count(*) from avaliacoes where autonomo_id = NEW.autonomo_id)
  where id = NEW.autonomo_id;
  return NEW;
end;
$$ language plpgsql;

create trigger trigger_atualiza_nota
after insert or update on avaliacoes
for each row execute function atualizar_nota_autonomo();

-- ──────────────────────────────────────────
--  FUNÇÃO: busca autônomos por distância (GPS)
-- ──────────────────────────────────────────
create or replace function buscar_autonomos_perto(
  lat_usuario double precision,
  lng_usuario double precision,
  raio_km     double precision default 10,
  categoria_filtro text default null
)
returns table (
  id uuid, nome text, categoria text, especialidade text,
  bairro text, nota_media numeric, total_avaliacoes int,
  verificado boolean, distancia_km double precision
) as $$
begin
  return query
  select
    a.id, a.nome, a.categoria, a.especialidade,
    a.bairro, a.nota_media, a.total_avaliacoes,
    a.verificado,
    round((ST_Distance(
      a.localizacao,
      ST_SetSRID(ST_MakePoint(lng_usuario, lat_usuario), 4326)::geography
    ) / 1000)::numeric, 1) as distancia_km
  from autonomos a
  where
    a.ativo = true
    and ST_DWithin(
      a.localizacao,
      ST_SetSRID(ST_MakePoint(lng_usuario, lat_usuario), 4326)::geography,
      raio_km * 1000
    )
    and (categoria_filtro is null or a.categoria = categoria_filtro)
  order by distancia_km asc;
end;
$$ language plpgsql;
