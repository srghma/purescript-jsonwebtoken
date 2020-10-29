module Jsonwebtoken.NotBeforeError where

import Control.Monad.Except
import Data.Bifunctor
import Data.Either
import Data.Function.Uncurried
import Data.List.NonEmpty
import Data.Maybe
import Data.Traversable
import Effect.Aff
import Effect.Uncurried
import Prelude
import Data.JSDate

import Foreign

data NotBeforeError

foreign import name :: NotBeforeError -> String

foreign import message :: NotBeforeError -> String

foreign import date :: NotBeforeError -> JSDate

foreign import _fromError
  :: forall a
   . Fn3
    (Maybe a)
    (a -> Maybe a)
    Error
    (Maybe NotBeforeError)

fromError :: Error -> Maybe NotBeforeError
fromError =
  runFn3
  _fromError
  Nothing
  Just
