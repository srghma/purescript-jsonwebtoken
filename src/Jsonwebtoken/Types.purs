module Jsonwebtoken.Types where

import Control.Alt ((<|>))
import Control.Monad.Error.Class (throwError)
import Data.DateTime (DateTime)
import Data.DateTime.Instant (fromDateTime, instant, toDateTime, unInstant)
import Data.Either (Either(..))
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Int (floor)
import Data.List.NonEmpty (singleton)
import Data.Maybe (Maybe(..), maybe)
import Data.Newtype (class Newtype, unwrap, wrap)
import Data.Traversable (traverse)
import Effect.Aff (Milliseconds(..))
import Foreign (ForeignError(..), readArray, readNumber, readString)
import Foreign.Generic (class Decode, class Encode, encode)
import Foreign.Generic.EnumEncoding (defaultGenericEnumOptions, genericDecodeEnum, genericEncodeEnum)
import Prelude (class Eq, class Ord, class Show, pure, show, ($), (*), (/), (<<<), (=<<), (>=>), (>>>))
import Jsonwebtoken.NumericDate

data Algorithm
  = HS256 -- HMAC using SHA-256 hash algorithm
  | HS384 -- HMAC using SHA-384 hash algorithm
  | HS512 -- HMAC using SHA-512 hash algorithm
  | RS256 -- RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
  | RS384 -- RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
  | RS512 -- RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
  | PS256 -- RSASSA-PSS using SHA-256 hash algorithm (only node ^6.12.0 OR >=8.0.0)
  | PS384 -- RSASSA-PSS using SHA-384 hash algorithm (only node ^6.12.0 OR >=8.0.0)
  | PS512 -- RSASSA-PSS using SHA-512 hash algorithm (only node ^6.12.0 OR >=8.0.0)
  | ES256 -- ECDSA using P-256 curve and SHA-256 hash algorithm
  | ES384 -- ECDSA using P-384 curve and SHA-384 hash algorithm
  | ES512 -- ECDSA using P-521 curve and SHA-512 hash algorithm
  -- | | None  -- No digital signature or MAC value included

derive instance genericAlgorithm :: Generic Algorithm _
derive instance eqAlgorithm :: Eq Algorithm
instance showAlgorithm :: Show Algorithm where show = genericShow

algorithmToInternal :: Algorithm -> String
algorithmToInternal = show

data Typ
  = JWT

derive instance genericTyp :: Generic Typ _
derive instance eqTyp :: Eq Typ
instance showTyp :: Show Typ where show = genericShow

type JOSEHeaders
  = { typ :: Typ
    , cty :: Maybe Typ
    , alg :: Algorithm
    , kid :: Maybe String
    }

defaultHeaders :: JOSEHeaders
defaultHeaders = { typ: JWT, cty: Nothing, alg: HS256, kid: Nothing }

-- | type Claims r
-- |   = { iss :: Maybe String
-- |     , sub :: Maybe String
-- |     , aud :: Maybe (Either String (Array String))
-- |     , exp :: Maybe NumericDate
-- |     , nbf :: Maybe NumericDate
-- |     , iat :: Maybe NumericDate
-- |     , jti :: Maybe String
-- |     , unregisteredClaims :: Maybe (Record r)
-- |     }

-- | data Verified

-- | data Unverified

-- | type Token a s
-- |   = { headers :: JOSEHeaders
-- |     , claims :: Claims a
-- |     }

-- | defaultClaims :: Claims ()
-- | defaultClaims =
-- |   { iss: Nothing
-- |   , sub: Nothing
-- |   , aud: Nothing
-- |   , exp: Nothing
-- |   , nbf: Nothing
-- |   , iat: Nothing
-- |   , jti: Nothing
-- |   , unregisteredClaims: Nothing
-- |   }

newtype SecretOrPublicKey = SecretOrPublicKey String

derive instance newtypeSecretOrPublicKey :: Newtype SecretOrPublicKey _
