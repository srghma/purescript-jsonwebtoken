module Jsonwebtoken.JwtErrors where

import Control.Monad.Except
import Data.Bifunctor
import Data.Either
import Data.Function.Uncurried
import Data.List.NonEmpty
import Data.Maybe
import Data.Traversable
import Effect.Aff
import Effect.Uncurried
import Foreign
import Prelude
import Data.Foldable as Foldable

import Jsonwebtoken.JsonWebTokenError (JsonWebTokenError)
import Jsonwebtoken.JsonWebTokenError as JsonWebTokenError
import Jsonwebtoken.NotBeforeError (NotBeforeError)
import Jsonwebtoken.NotBeforeError as NotBeforeError
import Jsonwebtoken.NumericDate (NumericDate)
import Jsonwebtoken.NumericDate as NumericDate
import Jsonwebtoken.TokenExpiredError (TokenExpiredError)
import Jsonwebtoken.TokenExpiredError as TokenExpiredError

data JwtErrors
  = JwtErrors__JsonWebTokenError JsonWebTokenError
  | JwtErrors__NotBeforeError NotBeforeError
  | JwtErrors__TokenExpiredError TokenExpiredError
  | JwtErrors__Other Error

errorToJwtErrors :: Error -> JwtErrors
errorToJwtErrors error =
  fromMaybe (JwtErrors__Other error) $ Foldable.oneOf
    [ JsonWebTokenError.fromError error <#> JwtErrors__JsonWebTokenError
    , TokenExpiredError.fromError error <#> JwtErrors__TokenExpiredError
    , NotBeforeError.fromError error <#> JwtErrors__NotBeforeError
    ]

catchJwtErrors :: ∀ t20 t23. Functor t20 ⇒ MonadError Error t20 ⇒ t20 t23 → t20 (Either JwtErrors t23)
catchJwtErrors = map (lmap errorToJwtErrors) <<< try
