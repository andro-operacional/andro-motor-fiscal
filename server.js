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
const forge = require('node-forge'); // lê certificados ICP-Brasil "legados" que o OpenSSL novo recusa
const { createClient } = require('@supabase/supabase-js'); // pra ler/gravar na base do sistema

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

/* ---- Conexão com a base do sistema (Supabase) ---- */
const SB_URL = process.env.SUPABASE_URL || '';
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || ''; // chave "service_role" — só fica aqui no servidor, nunca no navegador
const sb = (SB_URL && SB_KEY) ? createClient(SB_URL, SB_KEY, { auth: { persistSession: false } }) : null;

/* IDs do serviço de Caixa Postal (conforme doc do Serpro — ajustáveis por variável de ambiente no teste) */
const CX_SISTEMA   = 'CAIXAPOSTAL';
const CX_INDICADOR = process.env.CX_INDICADOR || 'INNOVAMSG63';          // indica se há mensagens novas (verbo Monitorar)
const CX_LISTA     = process.env.CX_LISTA     || 'MSGCONTRIBUINTE61';    // lista as mensagens (verbo Consultar)
const CX_DETALHE   = process.env.CX_DETALHE   || 'MSGDETALHAMENTO62';    // conteúdo de UMA mensagem por isn (verbo Consultar)
const CX_MAX_MSGS  = Number(process.env.CX_MAX_MSGS || 8);               // qtde máx. de mensagens que baixamos por cliente

/* ---- Certificado A1 (mTLS) ---- */
let _agent = null;
// Lê o .pfx e extrai chave+certificado com node-forge (compatível com certificados ICP-Brasil legados)
function loadIdentity() {
  let der;
  if (CERT_B64) der = forge.util.decode64(CERT_B64.replace(/\s+/g, ''));
  else der = fs.readFileSync(CERT_PATH).toString('binary');
  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, CERT_PASSWORD);
  // chave privada
  const shrouded = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  const plain = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];
  const keyBag = shrouded[0] || plain[0];
  if (!keyBag || !keyBag.key) throw new Error('Chave privada nao encontrada (senha do certificado errada?)');
  const keyPem = forge.pki.privateKeyToPem(keyBag.key);
  // certificados
  const certs = (p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || []).map(b => b.cert);
  if (!certs.length) throw new Error('Certificado nao encontrado no .pfx');
  const keyN = keyBag.key.n ? keyBag.key.n.toString(16) : null;
  const leaf = certs.find(c => c.publicKey && c.publicKey.n && c.publicKey.n.toString(16) === keyN) || certs[0];
  const certPem = forge.pki.certificateToPem(leaf);
  const caPem = certs.filter(c => c !== leaf).map(c => forge.pki.certificateToPem(c));
  return { key: keyPem, cert: certPem, ca: caPem };
}
function getAgent() {
  if (!_agent) {
    const id = loadIdentity();
    // só apresentamos chave+cert do cliente; a verificação do servidor usa as CAs padrão do Node
    _agent = new https.Agent({ key: id.key, cert: id.cert });
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

/* ---- Chamada genérica ao gateway (verbo = Consultar, Monitorar, Emitir, ...) ---- */
async function chamar(verbo, idServico, cnpjCliente, dados = {}) {
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
    'https://gateway.apiserpro.serpro.gov.br/integra-contador/v1/' + verbo,
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

/* ---- Caixa Postal: ler a lista de mensagens e o conteúdo de cada uma ---- */
// O Serpro devolve um campo "dados" que normalmente é um JSON em texto.
function parseDados(resp) {
  let d = resp && resp.dados;
  if (typeof d === 'string') { try { d = JSON.parse(d); } catch (e) { d = null; } }
  return d || {};
}
// Extrai a lista de mensagens (cada uma tem um "isn")
function coletarMensagens(listaResp) {
  const d = parseDados(listaResp);
  const cont = Array.isArray(d.conteudo) ? d.conteudo : (Array.isArray(d.listaMensagens) ? [{ listaMensagens: d.listaMensagens }] : []);
  let msgs = [];
  cont.forEach(c => {
    if (Array.isArray(c.listaMensagens)) msgs = msgs.concat(c.listaMensagens);
    else if (c && (c.isn || c.assuntoModelo)) msgs.push(c);
  });
  return msgs;
}
function pickIsn(m) { return m.isn || m.ISN || m.isnMensagem || m.numeroControle || ''; }
// Monta um HTML legível com o conteúdo das mensagens (vira o anexo)
function montarDocumento(nomeCliente, cnpj, detalhes) {
  const linhas = detalhes.map(det => {
    const c = (parseDados(det).conteudo && parseDados(det).conteudo[0]) || parseDados(det) || {};
    let corpo = c.corpoModelo || c.corpo || '';
    const vars = Array.isArray(c.variaveis) ? c.variaveis : [];
    vars.forEach((v, i) => { corpo = corpo.split('{' + i + '}').join(v); });
    const assunto = c.assuntoModelo || c.assunto || '(sem assunto)';
    const data = c.dataEnvio || '';
    return `<div style="border:1px solid #e3e3e3;border-radius:10px;padding:14px;margin:0 0 14px">
      <div style="font-weight:700;color:#452289;font-size:15px">${assunto}</div>
      <div style="color:#888;font-size:12px;margin:2px 0 10px">Enviada: ${data}</div>
      <div style="font-size:14px;line-height:1.5">${corpo || '(sem corpo)'}</div>
    </div>`;
  }).join('');
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
    <title>e-CAC ${nomeCliente}</title></head>
    <body style="font-family:Arial,Helvetica,sans-serif;color:#26203a;max-width:760px;margin:18px auto;padding:0 14px">
    <h2 style="color:#452289">Mensagens e-CAC — ${nomeCliente}</h2>
    <p style="color:#666;font-size:13px">CNPJ ${cnpj} · baixado em ${new Date().toLocaleString('pt-BR')} · via Serpro Integra Contador</p>
    ${linhas || '<p>Nenhuma mensagem.</p>'}
    </body></html>`;
}
// Lê a caixa postal de um cliente: indicador + lista + conteúdo. Retorna {novas, assuntos, anexo}.
async function lerCaixaPostal(cnpj, nomeCliente) {
  const ind = await chamar('Monitorar', CX_INDICADOR, cnpj);
  const temNovas = lerIndicadorNovas(ind);
  let msgs = [], listaErro = null;
  try {
    const lista = await chamar('Consultar', CX_LISTA, cnpj, { statusLeitura: '0', indicadorPagina: '0', ponteiroPagina: '00000000000000' });
    msgs = coletarMensagens(lista).filter(m => pickIsn(m));
  } catch (e) { listaErro = e.response?.data?.mensagens?.[0]?.texto || e.response?.data || e.message; }
  if (msgs.length > CX_MAX_MSGS) msgs = msgs.slice(0, CX_MAX_MSGS);
  const detalhes = [];
  const assuntos = [];
  for (const m of msgs) {
    if (m.assuntoModelo) assuntos.push(m.assuntoModelo);
    try {
      const det = await chamar('Consultar', CX_DETALHE, cnpj, { isn: String(pickIsn(m)) });
      detalhes.push(det);
    } catch (e) { /* ignora uma mensagem que falhe */ }
    await new Promise(r => setTimeout(r, 200));
  }
  let anexo = null;
  if (detalhes.length) {
    const html = montarDocumento(nomeCliente || cnpj, cnpj, detalhes);
    const b64 = Buffer.from(html, 'utf8').toString('base64');
    anexo = { nome: 'eCAC_' + cnpj + '_' + new Date().toISOString().slice(0, 10) + '.html', dataUrl: 'data:text/html;base64,' + b64, auto: true };
  }
  return { novas: temNovas === true, qtde: msgs.length, assuntos, anexo, listaErro };
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
    const r = await lerCaixaPostal(cnpj, req.body?.nome || '');
    res.json({ ok: true, cnpj, tem_mensagem_nova: r.novas, mensagens_baixadas: r.qtde, assuntos: r.assuntos, documento_gerado: r.anexo ? r.anexo.nome : null, lista_erro: r.listaErro || null });
  } catch (e) {
    res.status(500).json({ ok: false, cnpj, etapa: 'consulta', erro: e.response?.data || e.message });
  }
});

/* ---- Extrai "tem mensagem nova?" da resposta do indicador (formato do Serpro varia) ---- */
function lerIndicadorNovas(resp) {
  // a resposta traz um campo "dados" que normalmente é um JSON em texto
  let d = resp && resp.dados;
  if (typeof d === 'string') { try { d = JSON.parse(d); } catch (e) { d = null; } }
  const alvo = d || resp || {};
  let achou = null;
  (function busca(o) {
    if (achou !== null || !o || typeof o !== 'object') return;
    for (const k of Object.keys(o)) {
      if (/indicadorMensagensNovas/i.test(k)) { achou = o[k]; return; }
      if (typeof o[k] === 'object') busca(o[k]);
    }
  })(alvo);
  if (achou === null) return null;            // não conseguiu ler
  return Number(String(achou).replace(/\D/g, '')) > 0; // true = tem mensagem nova
}

/* 3) RODAR: verifica o e-CAC de TODOS os clientes ativos e grava na base do sistema.
   Body opcional: { "limite": 3 } pra testar com poucos clientes primeiro. */
app.post('/rodar', async (req, res) => {
  if (!autorizado(req, res)) return;
  if (!sb) return res.status(500).json({ ok: false, erro: 'Supabase nao configurado (faltam SUPABASE_URL e SUPABASE_SERVICE_KEY no Render)' });
  const limite = Number(req.body?.limite) || 0; // 0 = todos
  try {
    // 1. lê a base
    const { data: row, error } = await sb.from('app_state').select('data').eq('id', 'main').maybeSingle();
    if (error) throw error;
    const db = row?.data || {};
    db.clientes = Array.isArray(db.clientes) ? db.clientes : [];

    // 2. seleciona clientes ativos com CNPJ válido
    let alvos = db.clientes.filter(c => {
      const ativo = c.ativo !== false && c.etapa !== 'Perdido' && c.etapa !== 'Inativo';
      return ativo && String(c.cnpj || '').replace(/\D/g, '').length === 14;
    });
    if (limite > 0) alvos = alvos.slice(0, limite);

    const hoje = new Date().toISOString().slice(0, 10);
    let verificados = 0, comMensagem = 0;
    const falhas = [];

    // 3. consulta o e-CAC de cada um (indicador + lista + conteúdo) e anexa o documento
    for (const c of alvos) {
      const cnpj = String(c.cnpj).replace(/\D/g, '');
      try {
        const r = await lerCaixaPostal(cnpj, c.nome);
        c.fiscalMsg = r.novas;
        c.fiscalUltima = hoje;
        c.fiscalPor = 'Serpro (automático)';
        c.fiscalSituacao = r.novas ? 'Mensagem nova' : 'Regular';
        if (r.assuntos && r.assuntos.length) c.fiscalObs = r.assuntos.slice(0, 5).join(' · ');
        // substitui o documento automático anterior, mantendo anexos manuais
        c.fiscalAnexos = (Array.isArray(c.fiscalAnexos) ? c.fiscalAnexos : []).filter(a => !a.auto);
        if (r.anexo) c.fiscalAnexos.push(r.anexo);
        verificados++;
        if (r.novas) comMensagem++;
      } catch (e) {
        const msg = e.response?.data?.mensagens?.[0]?.texto || e.response?.data?.mensagem || e.message;
        c.fiscalUltima = hoje;
        c.fiscalPor = 'Serpro (erro)';
        c.fiscalObs = String(msg).slice(0, 180);
        falhas.push({ nome: c.nome || cnpj, cnpj, erro: String(msg).slice(0, 180) });
      }
      await new Promise(r => setTimeout(r, 350));
    }

    // 4. grava de volta na base (db.clientes já foi atualizado por referência)
    const { error: errSave } = await sb.from('app_state')
      .update({ data: db, updated_at: new Date().toISOString() })
      .eq('id', 'main');
    if (errSave) throw errSave;

    res.json({ ok: true, total_ativos: alvos.length, verificados, com_mensagem_nova: comMensagem, falhas });
  } catch (e) {
    res.status(500).json({ ok: false, etapa: 'rodar', erro: e.response?.data || e.message });
  }
});

app.listen(PORT, () => console.log('andro motor fiscal rodando na porta ' + PORT));
