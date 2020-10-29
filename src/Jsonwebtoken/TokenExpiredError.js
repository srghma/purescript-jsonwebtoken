const jwt = require("jsonwebtoken")

exports.name = function (error) { return error.name }

exports.message = function (error) { return error.message }

exports.expiredAt = function (error) { return error.expiredAt }

exports._fromError = function (nothing, just, error) {
  if (error instanceof jwt.TokenExpiredError) {
    return just(error)
  }

  return nothing
}
