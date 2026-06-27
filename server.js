/* =====================================================================
   andro · Motor Fiscal  —  Integração oficial Serpro Integra Contador
   Lê a Caixa Postal do e-CAC de um cliente (via procuração + certificado A1).
   Roda num servidor Node (ex: Render). NÃO roda no navegador.
   Segredos vêm das variáveis de ambiente / secret files do Render.
   ===================================================================== */
const express = require('express');
const https = require('https');
const fs = require('fs');
const axios = require('axios');

const app = express();
app.use(express.json());

/* ---- CORS (pra página de teste local conseguir chamar) ---- */
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'content-type, x-motor-secret');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

/* ---- Configuração (variáveis de ambiente / secret files no Render) ---- */
const PORT            = process.env.PORT || 3000;
const MOTOR_SECRET    = process.env.MOTOR_SECRET || '';            // senha simples que protege os endpoints de teste
const CONSUMER_KEY    = process.env.SERPRO_CONSUMER_KEY || '';
const CONSUMER_SECRET = process.env.SERPRO_CONSUMER_SECRET || '';
const CERT_B64        = process.env.SERPRO_CERT_PFX_BASE64 || '';          // certificado em base64 (texto seguro) — PREFERIDO
const CERT_PATH       = process.env.CERT_PATH || '/etc/secrets/andro.pfx'; // alternativa: arquivo .pfx (secret file)
const CERT_PASSWORD   = process.env.SERPRO_CERT_PASSWORD || '';
const ANDRO_CNPJ      = (process.env.ANDRO_CNPJ || '37922384000100').replace(/\D/g, '');

/* IDs do serviço de Caixa Postal (conforme doc do Serpro — ajustáveis por variável de ambiente no teste) */
const CX_SISTEMA   = 'CAIXAPOSTAL';
const CX_INDICADOR = process.env.CX_INDICADOR || 'INDICADORMENSAGENS62'; // indica se há mensagens novas
const CX_LISTA     = process.env.CX_LISTA     || 'MSGCONTRIBUINTE61';    // lista as mensagens

/* ---- Certificado A1 (mTLS) ---- */
let _agent = null;
function getPfx() {
  if (CERT_B64) return Buffer.from(CERT_B64.replace(/\s+/g, ''), 'base64'); // base64 limpo -> binário
  return fs.readFileSync(CERT_PATH);
}
function getAgent() {
  if (!_agent) {
    _agent = new https.Agent({
      pfx: getPfx(),
      passphrase: CERT_PASSWORD,
    });
  }
  return _agent;
}

/* ---- Token Serpro (válido até a meia-noite do dia seguinte; guardamos em memória) ---- */
let _token = null; // { access_token, jwt_token, exp }
async function getToken() {
  if (_token && Date.now() < _token.exp) return _token;
  const basic = Buffer.from(`${CONSUMER_KEY}:${CONSUMER_SECRET}`).toString('base64');
  const { data } = await axios.post(
    'https://autenticacao.sapi.serpro.gov.br/authenticate',
    'grant_type=client_credentials',
    {
      httpsAgent: getAgent(),
      headers: {
        Authorization: `Basic ${basic}`,
        'role-type': 'TERCEIROS',
        'content-type': 'application/x-www-form-urlencoded',
      },
      timeout: 30000,
    }
  );
  const ttl = (data.expires_in ? data.expires_in * 1000 : 3600 * 1000) - 60000;
  _token = { access_token: data.access_token, jwt_token: data.jwt_token, exp: Date.now() + ttl };
  return _token;
}

/* ---- Consulta genérica ao gateway (Consultar) ---- */
async function consultar(idServico, cnpjCliente, dados = {}) {
  const tok = await getToken();
  const body = {
    contratante:      { numero: ANDRO_CNPJ, tipo: 2 },
    autorPedidoDados: { numero: ANDRO_CNPJ, tipo: 2 },
    contribuinte:     { numero: String(cnpjCliente).replace(/\D/g, ''), tipo: 2 },
    pedidoDados: {
      idSistema: CX_SISTEMA,
      idServico,
      versaoSistema: '1.0',
      dados: JSON.stringify(dados),
    },
  };
  const { data } = await axios.post(
    'https://gateway.apiserpro.serpro.gov.br/integra-contador/v1/Consultar',
    body,
    {
      httpsAgent: getAgent(),
      headers: {
        Authorization: `Bearer ${tok.access_token}`,
        jwt_token: tok.jwt_token,
        'content-type': 'application/json',
      },
      timeout: 60000,
    }
  );
  return data;
}

/* ---- Proteção simples dos endpoints ---- */
function autorizado(req, res) {
  if (!MOTOR_SECRET || req.get('x-motor-secret') !== MOTOR_SECRET) {
    res.status(401).json({ erro: 'nao autorizado (x-motor-secret invalido)' });
    return false;
  }
  return true;
}

/* ---- Rotas ---- */
app.get('/', (_req, res) =>
  res.json({ ok: true, servico: 'andro motor fiscal', hora: new Date().toISOString() })
);

// 1) Testa SÓ a autenticação no Serpro (certificado + chaves)
app.post('/testar-auth', async (req, res) => {
  if (!autorizado(req, res)) return;
  try {
    const tok = await getToken();
    res.json({ ok: true, autenticou: true, tem_access_token: !!tok.access_token, tem_jwt_token: !!tok.jwt_token });
  } catch (e) {
    res.status(500).json({ ok: false, etapa: 'autenticacao', erro: e.response?.data || e.message });
  }
});

// 2) Testa a leitura da Caixa Postal de UM cliente (body: { "cnpj": "..." })
app.post('/testar-cliente', async (req, res) => {
  if (!autorizado(req, res)) return;
  const cnpj = String(req.body?.cnpj || '').replace(/\D/g, '');
  if (!cnpj) return res.status(400).json({ erro: 'informe o cnpj: { "cnpj": "00000000000000" }' });
  try {
    const indicador = await consultar(CX_INDICADOR, cnpj);
    let lista = null;
    try { lista = await consultar(CX_LISTA, cnpj); }
    catch (e) { lista = { erro: e.response?.data || e.message }; }
    res.json({ ok: true, cnpj, indicador, lista });
  } catch (e) {
    res.status(500).json({ ok: false, cnpj, etapa: 'consulta', erro: e.response?.data || e.message });
  }
});

app.listen(PORT, () => console.log('andro motor fiscal rodando na porta ' + PORT));
