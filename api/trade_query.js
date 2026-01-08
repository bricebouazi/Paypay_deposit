import crypto from 'crypto';
import forge from 'node-forge';



export default function handler(req, res) {
  const { out_trade_no } = req.query;

  if (!out_trade_no) {
    return res.status(400).json({ error: "Paramètre out_trade_no manquant" });
  }

  try {
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----
MIICXAIBAAKBgQCogX+em5Awhl9zNoWw0ta6b7PFTMx73Hx+ECWBZykbmS7ycvmb
JjCN82B8doP4ajKV9UqtE5YXugW05Eecg11DG8cQX4m5VQkmwEvxpzOsRvTcFh9h
HV6DeTbwpTHx1I3Sjd1V2IbpRYVTItw1MPHxTwT/jerLlf4j1LlhPse4fwIDAQAB
AoGABEvg/CNNRt92OZLPT9XgYbqNY990a0gQ6Iny2tzNgIWkW8wwrxMHM+dbs3C2
JrRWe9pYQBd6wToeASG87bGvxAauJXbMVCGJcYWz+17lms7Sxb8JrkL0zYwUsH0t
M8sY5dVPzVILYUZQe6qFf1RRU3RsApIfZQzeQ90VuiHEhUkCQQDUmjUPIgBSO9TD
QVNV9ZCftz6a1YpMnr0BXmcgo9n8s4zXvQjjkAWfFEwukNiNbGyeL5iHJt3WBUvN
BBQuLkZbAkEAyub5gNlBiMP3RUaCTM20BfvN7CH1+JJZtngWBjYBvHoSgo2W+hDi
eKvcDp6594dkQCi+ymi/ShyUuJDOSpAXrQJAXL4seT5+32CkTsz3ep8WCOZaFBcl
Lolsr+Urnax8kmUNAqu+7e5M1Xl4RjP/k6oBs/vVUNfem9dRmsy1tPOQ0wJBAIhk
4f4ajXI5gYRBFKA6ezS2g0OjxKxW/RWq/eso7NvdF4pJUd9B8Gt74860JoDds6dp
fG+mIEjak6LKPNJksHUCQGBZ9aUY8oxavOrkcxqLOAf/DI39+0I9PYQ/M1aJyOqD
3bxQp+7UpJh9dieeag7qT4TQ93F3x4ZoGFM+s4I6LaI=
-----END PRIVATE KEY-----`;  // PRIVATE_KEY

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
    const encryptedBiz = encryptBizContent(JSON.stringify(bizObj), privateKeyPem);
   
    const params = {
      charset: 'UTF-8',
      biz_content: encryptedBiz,
      partner_id: '200001860724', //  200002410911
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
      params
    });

  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
