{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE DeriveAnyClass    #-}

{-# OPTIONS -Wno-unused-matches   #-}
{-# OPTIONS -Wno-unused-top-binds #-}

import Yesod
import Kbgen
import Kbapi ( Query )
import Api ( queryApi )
import ApiEnv ( ApiConfig(..), runApiEnv )
import Logging
import Swipl
import GHC.Generics
import Data.List as List
import qualified Data.Text as T
import qualified Network.Wai
import qualified Network.HTTP.Types.Status as NetworkHTTPTypes
import Network.Wai.Handler.Warp (run)
import Data.Word ( Word64 )

newtype Healthy = Healthy Bool deriving ( Generic )

instance ToJSON Healthy where toJSON (Healthy status) = object [ "healthy" .= status ]

data App = App

mkYesod "App" [parseRoutes|
/querycheck QuerycheckR POST
/uploadkb UploadkbR POST
/api ApiR POST
/healthcheck HealthcheckR GET
|]

-- 64MB
useIncreasedSizeLimit :: Word64
useIncreasedSizeLimit = 64000000

instance Yesod App where
    maximumContentLength _thereIsOnly1AppHere (Just QuerycheckR) = Just useIncreasedSizeLimit
    maximumContentLength _thereIsOnly1AppHere (Just UploadkbR) = Just useIncreasedSizeLimit
    maximumContentLength _thereIsOnly1AppHere (Just ApiR) = Just useIncreasedSizeLimit
    maximumContentLength _thereIsOnly1AppHere _ = Nothing
    makeLogger _thereIsOnly1AppHere = customizedLogger
    messageLoggerSource _thereIsOnly1AppHere = messageLoggerWithoutSource

getHealthcheckR :: Handler Value
getHealthcheckR = returnJson (Healthy True)

logFactsInfo :: [ Kbgen.Fact ] -> Handler ()
logFactsInfo facts = do
    $logInfo $ T.pack ("Num facts received: " ++ show (length facts))

postQuerycheckR :: Handler Value
postQuerycheckR = do
    facts <- requireCheckJsonBody :: Handler [ Kbgen.Fact ]
    logFactsInfo facts
    results <- liftIO (queryEngine facts)
    postQuerycheck' results

postUploadkbR :: Handler Value
postUploadkbR = do
    facts <- requireCheckJsonBody :: Handler [ Kbgen.Fact ]
    logFactsInfo facts
    kb_filename <- liftIO (writeFactsToTempFile facts)
    $logInfo $ T.pack ("KB written to: " ++ kb_filename)
    returnJson $ object [ "kb_location" .= kb_filename ]

postApiR :: Handler Value
postApiR = do
    kbFilename <- requireKbFilename
    $logInfo $ T.pack ("API query request for kb: " ++ kbFilename)
    query <- requireCheckJsonBody :: Handler Query
    let apiConfig = ApiConfig { apiEnvKbFilename = kbFilename }
    result <- liftIO (runApiEnv apiConfig (queryApi query))
    $logInfo "API query finished"
    returnJson result

requireKbFilename :: Handler String
requireKbFilename = do
    kbFilename <- lookupGetParam "kb_location"
    case kbFilename of
        Just path -> pure (T.unpack path)
        Nothing -> invalidArgs [ "missing query parameter: kb_location" ]

newtype Timeout = Timeout Bool deriving ( Show, Eq )

receivedTimeout :: QueryEngineResult -> Timeout
receivedTimeout = Timeout . receivedTimeout'

receivedTimeout' :: QueryEngineResult -> Bool
receivedTimeout' result = null (Swipl.stdout result) && "timeout:" `List.isPrefixOf` Swipl.stderr result

postQuerycheck' :: QueryEngineResult -> Handler Value
postQuerycheck' results = postQuerycheck'' (receivedTimeout results) results

postQuerycheck'' :: Timeout -> QueryEngineResult -> Handler Value
postQuerycheck'' (Timeout True) _ = returnGatewayTimeout504
postQuerycheck'' (Timeout False) results = returnJson results

returnGatewayTimeout504 :: Handler Value
returnGatewayTimeout504 = returnBodylessHttpStatusCode NetworkHTTPTypes.gatewayTimeout504

returnBodylessHttpStatusCode :: NetworkHTTPTypes.Status -> Handler Value
returnBodylessHttpStatusCode status = sendWaiResponse (Network.Wai.responseBuilder status [] mempty)

main :: IO ()
main = do
    waiApp <- toWaiAppPlain App
    run 3000 $ defaultMiddlewaresNoLogging waiApp
