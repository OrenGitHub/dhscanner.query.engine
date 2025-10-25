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
import qualified Network.HTTP.Types.Status
import System.Log.FastLogger ( LogStr, toLogStr )
import Network.Wai.Handler.Warp (run)
import System.Directory (getTemporaryDirectory)
import qualified Network.Wai.Middleware.RequestLogger as Wai
import System.Process ( proc, readCreateProcessWithExitCode )
import Data.Time ( UTCTime, defaultTimeLocale, parseTimeM, formatTime )
import System.IO ( Handle, openTempFile, hPutStr, hClose )



data Healthy = Healthy Bool deriving ( Generic )

instance ToJSON Healthy where toJSON (Healthy status) = object [ "healthy" .= status ]

data App = App

mkYesod "App" [parseRoutes|
/querycheck QuerycheckR POST
/healthcheck HealthcheckR GET
|]

instance Yesod App

getHealthcheckR :: Handler Value
getHealthcheckR = returnJson (Healthy True)

postQuerycheckR :: Handler Value
postQuerycheckR = do
    facts <- requireCheckJsonBody :: Handler [ Kbgen.Fact ]
    results <- liftIO (queryEngine facts)
    returnJson results

data QueryEngineResult
   = QueryEngineResult
     {
         stdout :: String,
         stderr :: String
     }
     deriving (Show, Generic, ToJSON)

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
    hPutStr handle (List.unlines (List.map show facts))
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

runSwipl :: FilePath -> IO (Stdout, Stderr)
runSwipl mainFile = do
  let args = ["--quiet", "-s", mainFile, "-g", "main", "-t", "halt"]
  (_, out, err) <- readCreateProcessWithExitCode (proc "swipl" args) ""
  pure (Stdout out, Stderr err)

runSwiplWithTimeout :: FilePath -> IO (Maybe (Stdout, Stderr))
runSwiplWithTimeout path = timeout swiplTimeLimitMicroseconds (runSwipl path)

jsonify :: Maybe (Stdout, Stderr) -> QueryEngineResult
jsonify (Just (Stdout o, Stderr e)) = QueryEngineResult { stdout = o, stderr = e }
jsonify Nothing = QueryEngineResult { stdout = "", stderr = "timeout: " ++ (show swiplTimeLimitSeconds) }

dateFormatter' :: Maybe UTCTime -> String 
dateFormatter' (Just t) = formatTime defaultTimeLocale "[%d/%m/%Y ( %H:%M:%S )]" t
dateFormatter' Nothing = "[00/00/0000 ( 00:00:00 )]"

dateFormatter :: String -> String
dateFormatter date = dateFormatter' (parseTimeM True defaultTimeLocale "%d/%b/%Y:%T %Z" date :: Maybe UTCTime)

logify :: String -> Network.Wai.Request -> Network.HTTP.Types.Status.Status -> String
logify date req _status = let
    datePart = dateFormatter date
    method = BS.unpack (Network.Wai.requestMethod req)
    url = BS.unpack (Network.Wai.rawPathInfo req)
    in datePart ++ " [Info#(Wai)] " ++ method ++ " " ++ url ++ "\n"

formatter :: Network.Wai.Logger.ZonedDate -> Network.Wai.Request -> Network.HTTP.Types.Status.Status -> Maybe Integer -> LogStr
formatter date req status _responseSize = toLogStr (logify (BS.unpack date) req status)

loggerSettings :: Wai.RequestLoggerSettings
loggerSettings = Wai.defaultRequestLoggerSettings { Wai.outputFormat = Wai.CustomOutputFormat formatter }

main :: IO ()
main = do
    waiApp <- toWaiAppPlain App
    myLoggingMiddleware <- Wai.mkRequestLogger loggerSettings
    let middleware = myLoggingMiddleware . defaultMiddlewaresNoLogging
    run 3000 $ middleware waiApp
