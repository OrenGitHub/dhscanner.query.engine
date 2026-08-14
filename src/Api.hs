module Api
    ( queryApi
    ) where

import Kbapi
import qualified Content
import ApiEnv (ApiEnv)
import qualified ConstStringsMatchingApi
import qualified HttpGetHandlerRequestObjectApi
import qualified UnauthenticatedHttpPostHandlerRequestObjectApi
import qualified AuthenticatedHttpPostHandlerRequestObjectApi

queryApi :: Query -> ApiEnv QueryResult
queryApi (ConstStringsMatching q) = ConstStringsMatchingApi.query q
queryApi (HttpGetHandlerRequestObject q) = HttpGetHandlerRequestObjectApi.query q
queryApi (UnauthenticatedHttpPostHandlerRequestObject q) = UnauthenticatedHttpPostHandlerRequestObjectApi.query q
queryApi (AuthenticatedHttpPostHandlerRequestObject q) = AuthenticatedHttpPostHandlerRequestObjectApi.query q
queryApi _ = pure (FoundConstStringsMatching Content.FoundConstStringsMatching { Content.foundConstStringsMatchingThisRegex = "", Content.foundConstStringsMatchesTotal = 0, Content.foundConstStringsMatches = [] })
