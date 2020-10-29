module Jsonwebtoken.JsonWebTokenError where

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

data JsonWebTokenError

foreign import name :: JsonWebTokenError -> String

foreign import message :: JsonWebTokenError -> String

foreign import _fromError
  :: forall a
   . Fn3
    (Maybe a)
    (a -> Maybe a)
    Error
    (Maybe JsonWebTokenError)

fromError :: Error -> Maybe JsonWebTokenError
fromError =
  runFn3
  _fromError
  Nothing
  Just
