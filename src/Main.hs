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
import GHC.Generics
import Data.List as List
import System.Timeout (timeout)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.ByteString.Char8 as BS
import qualified Network.Wai
import qualified Network.Wai.Logger
import qualified Network.HTTP.Types.Status as NetworkHTTPTypes
import Yesod.Core.Types (Logger(..))
import System.Log.FastLogger ( LogStr, toLogStr, newStdoutLoggerSet, newTimeCache, defaultBufSize )
import Network.Wai.Handler.Warp (run)
import System.Directory (getTemporaryDirectory)
import qualified Network.Wai.Middleware.RequestLogger as Wai
import System.Process ( proc, createProcess, waitForProcess, ProcessHandle, CreateProcess(..), StdStream(..), terminateProcess )
import System.Exit ( ExitCode(..) )
import Control.Concurrent ( forkIO, threadDelay, killThread, ThreadId )
import Control.Exception ( finally, evaluate )
import Control.Monad ( join )
import Data.Time ( UTCTime, defaultTimeLocale, parseTimeM, formatTime )
import System.IO ( Handle, openTempFile, hPutStr, hClose, hGetContents )
import Data.Word ( Word64 )

newtype Healthy = Healthy Bool deriving ( Generic )

instance ToJSON Healthy where toJSON (Healthy status) = object [ "healthy" .= status ]

data App = App

mkYesod "App" [parseRoutes|
/querycheck QuerycheckR POST
/healthcheck HealthcheckR GET
|]

-- 64MB
useIncreasedSizeLimit :: Word64
useIncreasedSizeLimit = 64000000

-- Shared time format for all logging
customTimeFormat :: String
customTimeFormat = "[%d/%m/%Y ( %H:%M:%S )]"

customizedLogger :: IO Logger
customizedLogger = do
    _loggerSet <- newStdoutLoggerSet defaultBufSize
    _formatter <- newTimeCache (BS.pack customTimeFormat)
    return $ Logger _loggerSet _formatter

instance Yesod App where
    maximumContentLength _thereIsOnly1AppHere (Just QuerycheckR) = Just useIncreasedSizeLimit
    maximumContentLength _thereIsOnly1AppHere _ = Nothing
    makeLogger _thereIsOnly1AppHere = customizedLogger

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

newtype Timeout = Timeout Bool deriving ( Show, Eq )

receivedTimeout :: QueryEngineResult -> Timeout
receivedTimeout = Timeout . receivedTimeout'

receivedTimeout' :: QueryEngineResult -> Bool
receivedTimeout' result = null (stdout result) && "timeout:" `List.isPrefixOf` stderr result

data QueryEngineResult
   = QueryEngineResult
     {
         stdout :: String,
         stderr :: String
     }
     deriving (Show, Generic, ToJSON)

postQuerycheck' :: QueryEngineResult -> Handler Value
postQuerycheck' results = postQuerycheck'' (receivedTimeout results) results

postQuerycheck'' :: Timeout -> QueryEngineResult -> Handler Value
postQuerycheck'' (Timeout True) _ = returnGatewayTimeout504
postQuerycheck'' (Timeout False) results = returnJson results

returnGatewayTimeout504 :: Handler Value
returnGatewayTimeout504 = returnBodylessHttpStatusCode NetworkHTTPTypes.gatewayTimeout504

returnBodylessHttpStatusCode :: NetworkHTTPTypes.Status -> Handler Value
returnBodylessHttpStatusCode status = sendWaiResponse (Network.Wai.responseBuilder status [] mempty)

newtype Stdout = Stdout String deriving ( Show, Eq )
newtype Stderr = Stderr String deriving ( Show, Eq )

queryEngine :: [ Kbgen.Fact ] -> IO QueryEngineResult
queryEngine facts = do
    kb_filename <- writeFactsToTempFile facts
    main_filename <- instantiateTemplate kb_filename
    resultsOrTimeout <- runSwiplWithTimeout main_filename
    pure (jsonify resultsOrTimeout)

writeFactsToTempFile :: [ Kbgen.Fact ] -> IO FilePath
writeFactsToTempFile facts = do
    tmpDir <- getTemporaryDirectory
    (filename, handle) <- openTempFile tmpDir "kb_XXXXXXXX.pl"
    writeFactsToFileHandle facts filename handle

writeFactsToFileHandle :: [Kbgen.Fact] -> FilePath -> Handle -> IO FilePath
writeFactsToFileHandle facts filename handle = do
    hPutStr handle (List.unlines (List.map prologify facts))
    hClose handle
    pure filename

instantiateTemplate :: FilePath -> IO FilePath
instantiateTemplate kb_filename = do
    template <- readTemplate "template.pl"
    adjusted <- adjustTemplate kb_filename template
    saveAsMainFile adjusted

readTemplate :: FilePath -> IO T.Text
readTemplate = TIO.readFile

adjustTemplate :: FilePath -> T.Text -> IO T.Text
adjustTemplate kb_filename template = pure (T.replace "{KNOWLEDGE_BASE}" (T.pack kb_filename) template)

saveAsMainFile :: T.Text -> IO FilePath
saveAsMainFile content = do
    tmpDir <- getTemporaryDirectory
    (path, handle) <- openTempFile tmpDir "main_XXXXXXXX.pl"
    writeMainFileHandle content path handle

writeMainFileHandle :: T.Text -> FilePath -> Handle -> IO FilePath
writeMainFileHandle content path handle = do
    TIO.hPutStr handle content
    hClose handle
    pure path

-- 3 minutes timeout
swiplTimeLimitSeconds :: Word
swiplTimeLimitSeconds = 180

-- convert to signed + microseconds for actual OS execution
swiplTimeLimitMicroseconds :: Int
swiplTimeLimitMicroseconds = fromIntegral (swiplTimeLimitSeconds * 1000000)

swiplArgs :: FilePath -> [ String ]
swiplArgs path = ["--quiet", "-s", path, "-g", "main", "-t", "halt"]

swiplProcessConfig :: FilePath -> CreateProcess
swiplProcessConfig path = (proc "swipl" (swiplArgs path)) {
    std_out = CreatePipe,
    std_err = CreatePipe,
    create_group = True
}

createSwiplProcess :: FilePath -> IO (Maybe (Handle, Handle, ProcessHandle))
createSwiplProcess path = do
    (mOut, mErr, _, ph) <- createProcess (swiplProcessConfig path)
    pure (case (mOut, mErr) of { (Just out, Just err) -> Just (out, err, ph); _ -> Nothing })

killSwiplProcess :: ProcessHandle -> IO ()
killSwiplProcess ph = do { terminateProcess ph; threadDelay 1000000; terminateProcess ph }

setupTimeoutKiller :: ProcessHandle -> IO ThreadId
setupTimeoutKiller ph = forkIO (do { threadDelay swiplTimeLimitMicroseconds; killSwiplProcess ph })

readProcessOutput' :: ExitCode -> String -> String -> Maybe (Stdout, Stderr)
readProcessOutput' ExitSuccess out err = Just (Stdout out, Stderr err)
readProcessOutput' _ _ _ = Nothing

readProcessOutput :: Handle -> Handle -> ProcessHandle -> IO (Maybe (Stdout, Stderr))
readProcessOutput hOut hErr ph = do
    out <- hGetContents hOut
    err <- hGetContents hErr
    exitCode <- waitForProcess ph
    out' <- evaluate (length out `seq` out)
    err' <- evaluate (length err `seq` err)
    pure (readProcessOutput' exitCode out' err')

runProcessWithTimeout :: Handle -> Handle -> ProcessHandle -> IO (Maybe (Stdout, Stderr))
runProcessWithTimeout hOut hErr ph = do
    timeoutThread <- setupTimeoutKiller ph
    let processAction = readProcessOutput hOut hErr ph
    mResult <- timeout swiplTimeLimitMicroseconds processAction `finally` killThread timeoutThread
    pure (join mResult)

runSwiplWithTimeout' :: Maybe (Handle, Handle, ProcessHandle) -> IO (Maybe (Stdout, Stderr))
runSwiplWithTimeout' (Just (hOut, hErr, ph)) = runProcessWithTimeout hOut hErr ph
runSwiplWithTimeout' _ = pure Nothing

runSwiplWithTimeout :: FilePath -> IO (Maybe (Stdout, Stderr))
runSwiplWithTimeout path = createSwiplProcess path >>= runSwiplWithTimeout'

jsonify :: Maybe (Stdout, Stderr) -> QueryEngineResult
jsonify (Just (Stdout o, Stderr e)) = QueryEngineResult { stdout = o, stderr = e }
jsonify Nothing = QueryEngineResult { stdout = "", stderr = "timeout: " ++ (show swiplTimeLimitSeconds) }

dateFormatter' :: Maybe UTCTime -> String
dateFormatter' (Just t) = formatTime defaultTimeLocale customTimeFormat t
dateFormatter' Nothing = "[00/00/0000 ( 00:00:00 )]"

dateFormatter :: String -> String
dateFormatter date = dateFormatter' (parseTimeM True defaultTimeLocale "%d/%b/%Y:%T %Z" date :: Maybe UTCTime)

logify :: String -> Network.Wai.Request -> NetworkHTTPTypes.Status -> String
logify date req _status = let
    datePart = dateFormatter date
    method = BS.unpack (Network.Wai.requestMethod req)
    url = BS.unpack (Network.Wai.rawPathInfo req)
    in datePart ++ " [Info#(Wai)] " ++ method ++ " " ++ url ++ "\n"

formatter :: Network.Wai.Logger.ZonedDate -> Network.Wai.Request -> NetworkHTTPTypes.Status -> Maybe Integer -> LogStr
formatter date req status _responseSize = toLogStr (logify (BS.unpack date) req status)

loggerSettings :: Wai.RequestLoggerSettings
loggerSettings = Wai.defaultRequestLoggerSettings { Wai.outputFormat = Wai.CustomOutputFormat formatter }

main :: IO ()
main = do
    waiApp <- toWaiAppPlain App
    myLoggingMiddleware <- Wai.mkRequestLogger loggerSettings
    let middleware = myLoggingMiddleware . defaultMiddlewaresNoLogging
    run 3000 $ middleware waiApp
