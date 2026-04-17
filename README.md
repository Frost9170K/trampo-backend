# 🟢 Trampo — Backend

API do marketplace de autônomos Trampo.

---

## ⚡ Como rodar (passo a passo)

### 1. Instale o Node.js
Acesse https://nodejs.org e baixe a versão **LTS**.
Após instalar, abra o terminal e confirme:
```
node --version
```

### 2. Crie a conta no Supabase (banco de dados gratuito)
1. Acesse https://supabase.com e crie uma conta
2. Clique em "New Project" → dê o nome **trampo**
3. Escolha a região **South America (São Paulo)**
4. Após criar, vá em **SQL Editor** e cole todo o conteúdo do arquivo `banco.sql` e clique em **Run**
5. Vá em **Settings → API** e copie:
   - `Project URL` → vai no `.env` como `SUPABASE_URL`
   - `anon public` key → vai no `.env` como `SUPABASE_KEY`

### 3. Configure o ambiente
Na pasta do projeto, copie o arquivo de exemplo:
```
cp .env.example .env
```
Abra o `.env` e preencha com os dados do Supabase.

### 4. Instale as dependências
```
npm install
```

### 5. Rode o servidor
```
npm run dev
```

Você verá:
```
🟢 Trampo API rodando em http://localhost:3000
```

### 6. Teste se está funcionando
Abra o navegador em: http://localhost:3000/ping

Deve retornar:
```json
{ "status": "ok", "app": "Trampo API", "versao": "1.0.0" }
```

---

## 📡 Rotas disponíveis

| Método | Rota | Descrição |
|--------|------|-----------|
| POST | /pre-cadastro | Salva pré-cadastro do formulário |
| POST | /autonomos/cadastro | Cadastro completo de autônomo |
| POST | /autonomos/login | Login do autônomo |
| GET  | /autonomos | Lista autônomos (com filtros e GPS) |
| GET  | /autonomos/:id | Perfil público do autônomo |
| GET  | /autonomos/painel/dados | Painel privado (requer token) |
| GET  | /autonomos/painel/metricas | Métricas da semana (requer token) |
| PUT  | /autonomos/painel/perfil | Atualizar perfil (requer token) |
| POST | /usuarios/cadastro | Cadastro de cliente |
| POST | /usuarios/login | Login de cliente |
| POST | /pedidos | Criar pedido/contratação |
| GET  | /pedidos | Listar pedidos do usuário |
| PATCH| /pedidos/:id/concluir | Confirmar conclusão do serviço |
| POST | /avaliacoes | Avaliar serviço concluído |
| POST | /servicos | Adicionar serviço ao perfil |
| DELETE| /servicos/:id | Remover serviço |
| GET  | /categorias | Listar categorias com contagem |
| GET  | /ping | Health check |

---

## 💰 Lógica de pagamento (escrow)

```
Cliente paga → status: "aguardando_pagamento"
Pagar.me confirma → status: "pago"
Autônomo inicia → status: "em_andamento"
Cliente confirma → status: "concluido" → pagamento liberado
```

A taxa da plataforma (10%) é calculada automaticamente.

---

## 📁 Estrutura do projeto

```
trampo-backend/
├── server.js       ← API completa
├── banco.sql       ← Tabelas e funções do banco
├── package.json    ← Dependências
├── .env.example    ← Modelo de variáveis de ambiente
├── .env            ← Suas credenciais (não suba no GitHub!)
└── README.md       ← Este arquivo
```

---

Feito com 💚 — Trampo, Porto Alegre
