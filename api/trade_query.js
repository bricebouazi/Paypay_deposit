import crypto from 'crypto';
import forge from 'node-forge';
import fs from 'fs';




export default function handler(req, res) {
  const { out_trade_no } = req.query;

  if (!out_trade_no) {
    return res.status(400).json({ error: "Paramètre out_trade_no manquant" });
  }

  try {
    
    //const privatek = process.env.TESTKEY?.replace(/\\n/g, '\n');
    //const privateKeyPem = process.env.PRIVATE_KEY?.replace(/\\n/g, '\n');

    function loadPrivateKey(filePath) {
        const rawKey = fs.readFileSync(filePath, 'utf8');
        const cleanKey = rawKey.replace(/\r\n|\r/g, '\n').trim(); // Remove \r\n do Windows

        //console.log(cleanKey, 'Chave privada carregada do arquivo.');

        if (!cleanKey.includes('-----BEGIN PRIVATE KEY-----') || 
            !cleanKey.includes('-----END PRIVATE KEY-----')) {
            throw new Error('the file does not contain a valid PEM private key');
        }

        try {
            forge.pki.privateKeyFromPem(cleanKey); // Testa se forge aceita
            console.log('private key loaded and valid for node-forge.');
            return cleanKey;
        } catch (e) {
            throw new Error('Chave privada inválida para node-forge: ' + e.message);
        }
    }

    function loadPrivateKeyFromString(pemString) {
    if (typeof pemString !== 'string' || pemString.trim() === '') {
        throw new Error('La clé privée doit être une string PEM non vide');
    }

    // Normalisation : supporte \n échappés (Vercel) ou vrais retours ligne
    const cleanKey = pemString
        .replace(/\\n/g, '\n')   // IMPORTANT pour les env vars
        .replace(/\r/g, '')
        .trim();

    const isPKCS1 =
        cleanKey.includes('-----BEGIN RSA PRIVATE KEY-----') &&
        cleanKey.includes('-----END RSA PRIVATE KEY-----');

    const isPKCS8 =
        cleanKey.includes('-----BEGIN PRIVATE KEY-----') &&
        cleanKey.includes('-----END PRIVATE KEY-----');

    if (!isPKCS1 && !isPKCS8) {
        throw new Error(
        'Format PEM invalide (attendu : RSA PRIVATE KEY ou PRIVATE KEY)'
        );
    }

    try {
        // Validation node-forge
        forge.pki.privateKeyFromPem(cleanKey);
        console.log('✔ Clé privée valide pour node-forge');
        return cleanKey;
    } catch (e) {
        throw new Error('Clé privée invalide pour node-forge : ' + e.message);
    }
    }

    function encryptBizContent(bizContent, pem) {
      const buffer = Buffer.from(bizContent, 'utf8');
      const chunkSize = 117;
      const chunks = [];

      for (let i = 0; i < buffer.length; i += chunkSize) {
        const encrypted = crypto.privateEncrypt(
          {
            key: pem,
            padding: crypto.constants.RSA_PKCS1_PADDING,
          },
          buffer.slice(i, i + chunkSize)
        );
        chunks.push(encrypted);
      }
      return Buffer.concat(chunks).toString('base64');
    }

    function generateSignature(params, pem) {
      const keys = Object.keys(params)
        .filter(k => k !== 'sign' && k !== 'sign_type' && params[k] !== '')
        .sort();

      const signString = keys.map(k => `${k}=${params[k]}`).join('&');

      const privateKey = forge.pki.privateKeyFromPem(pem);
      const md = forge.md.sha1.create();
      md.update(signString, 'utf8');

      return forge.util.encode64(privateKey.sign(md));
    }

    const bizObj = { out_trade_no };
    //const privateKeyPem=loadPrivateKeyFromString(privatek);
    const privateKeyPem = loadPrivateKey(path.join(__dirname, 'rsa-keys/private_key.pem'));
    const encryptedBiz = encryptBizContent(JSON.stringify(bizObj), privateKeyPem);
   
    const params = {
      charset: 'UTF-8',
      biz_content: encryptedBiz,
      partner_id: process.env.partner_id, //  200002410911
      service: 'trade_query',
      request_no: "REQ" + Date.now(),
      format: 'JSON',
      sign_type: 'RSA',
      version: '1.0',
      timestamp: new Date().toISOString().replace(/T/, ' ').replace(/\..+/, ''),
      language: 'en',
    };

    params.sign = generateSignature(params, privateKeyPem);

    const encodedParams = Object.keys(params)
      .sort()
      .map(k => `${k}=${encodeURIComponent(params[k])}`)
      .join('&');

    res.status(200).json({
      full_query_string: encodedParams,
      privateKeyPem:privateKeyPem,
      params
    });

  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
