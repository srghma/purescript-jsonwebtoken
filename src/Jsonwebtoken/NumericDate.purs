module Jsonwebtoken.NumericDate where

import Data.DateTime
import Data.DateTime.Instant
import Data.Time.Duration
import Prelude

import Data.Either (Either(..))
import Data.Int (floor, toNumber)
import Data.Maybe (Maybe(..), maybe)
import Data.Newtype (class Newtype, unwrap, wrap)
import Foreign (ForeignError(..), readArray, readNumber, readString)
import Foreign.Generic (class Decode, class Encode, encode)
import Foreign.Generic.EnumEncoding (defaultGenericEnumOptions, genericDecodeEnum, genericEncodeEnum)

-- NumericDate is an Math.floor(seconds)
-- but seconds are in integer

newtype NumericDate = NumericDate Int

derive instance newtypeNumericDate :: Newtype NumericDate _

derive instance eqNumericDate :: Eq NumericDate

derive instance ordNumericDate :: Ord NumericDate

instance showNumericDate :: Show NumericDate where
  show (NumericDate x) = "(NumericDate " <> show x <> ")"

toSeconds :: NumericDate -> Seconds
toSeconds (NumericDate secondsInt) = Seconds (toNumber secondsInt)

fromSeconds :: Seconds -> NumericDate
fromSeconds (Seconds secondsNumber) = NumericDate (floor secondsNumber)
