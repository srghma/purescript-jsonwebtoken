const jwt = require("jsonwebtoken")

exports.name = function (error) { return error.name }

exports.message = function (error) { return error.message }

exports._fromError = function (nothing, just, error) {
  if (error instanceof jwt.JsonWebTokenError) {
    return just(error)
  }

  return nothing
}
