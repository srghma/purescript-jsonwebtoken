module Jsonwebtoken.TokenExpiredError where

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

import Data.Time.Duration (Seconds(..))

data TokenExpiredError

foreign import name :: TokenExpiredError -> String

foreign import message :: TokenExpiredError -> String

foreign import expiredAt :: TokenExpiredError -> Seconds

foreign import _fromError
  :: forall a
   . Fn3
    (Maybe a)
    (a -> Maybe a)
    Error
    (Maybe TokenExpiredError)

fromError :: Error -> Maybe TokenExpiredError
fromError =
  runFn3
  _fromError
  Nothing
  Just
