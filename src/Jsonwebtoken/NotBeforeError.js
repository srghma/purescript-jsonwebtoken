const jwt = require("jsonwebtoken")

exports.name = function (error) { return error.name }

exports.message = function (error) { return error.message }

exports.date = function (error) { return error.date }

exports._fromError = function (nothing, just, error) {
  if (error instanceof jwt.NotBeforeError) {
    return just(error)
  }

  return nothing
}
