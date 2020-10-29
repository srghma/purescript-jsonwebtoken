const jwt = require("jsonwebtoken")

// exports._decode = (just, nothing, token) => {
//   try {
//     return normalizeClaims(
//       jwt.decode(token, { complete: true, json: false }),
//       just,
//       nothing
//     )
//   } catch (_) {
//     return nothing
//   }
// }

function doNothingAffCanceller(cancelError, onCancelerError, onCancelerSuccess) {
  onCancelerSuccess()
}

exports._verify = function(complete, token, secretOrPublicKey, options) {
  return function (onError, onSuccess) {
    jwt.verify(
      token,
      secretOrPublicKey,
      {
        complete:         complete,

        // json: false, // not an option, just in case

        algorithms:       options.algorithms,
        audience:         options.audience,  // Eg: "urn:foo", /urn:f[o]{2}/, [/urn:f[o]{2}/, "urn:bar"]

        issuer:           options.issuer, // (optional)
        ignoreExpiration: false,
        ignoreNotBefore:  false,
        subject:          options.subject,
        clockTolerance:   options.clockTolerance, // default - 0

        maxAge:           options.maxAge,        // how it is different from exp and nbf?
        clockTimestamp:   options.clockTimestamp, // use default current time - https://github.com/auth0/node-jsonwebtoken/blob/88cb9df18a1d2a7b24f8cfeaa6f5f5b87d2c027f/verify.js#L50

        nonce:            options.nonce,
      },
      function (err, res) {
        if (err) {
          onError(err)
        } else {
          onSuccess(res)
        }
      }
    )

    return doNothingAffCanceller
  }
}

// exports._sign = (payload, unregisteredClaims, secret, options) => {
//   const fullPayload = unregisteredClaims
//     ? Object.assign({}, payload, unregisteredClaims)
//     : payload

//   return new Promise(function (resolve, reject) {
//     jwt.sign(fullPayload, secret, options, function (error, token) {
//       if (error) {
//         return reject(error)
//       }

//       resolve(token)
//     })
//   })
// }
