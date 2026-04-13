module Logging
    ( customizedLogger
    , messageLoggerWithoutSource
    , customTimeFormat
    ) where

import qualified Data.Text as T
import qualified Data.ByteString.Char8 as BS
import Yesod.Core.Types (Logger(..))
import Yesod.Core (LogLevel(..))
import System.Log.FastLogger ( LogStr, LoggerSet, toLogStr, newStdoutLoggerSet, newTimeCache, defaultBufSize, fromLogStr, pushLogStrLn )
import Data.Time ( defaultTimeLocale, formatTime, getZonedTime )

-- Shared time format for all logging
customTimeFormat :: String
customTimeFormat = "[%d/%m/%Y ( %H:%M:%S )]"

customizedLogger :: IO Logger
customizedLogger = do
    _loggerSet <- newStdoutLoggerSet defaultBufSize
    _formatter <- newTimeCache (BS.pack customTimeFormat)
    return $ Logger _loggerSet _formatter

messageLoggerWithoutSource :: Logger -> loc -> T.Text -> LogLevel -> LogStr -> IO ()
messageLoggerWithoutSource (Logger loggerSetValue _) _loc _source level =
    messageLoggerWithoutSource' level loggerSetValue

messageLoggerWithoutSource' :: LogLevel -> LoggerSet -> LogStr -> IO ()
messageLoggerWithoutSource' LevelDebug = messageDebugLoggerWithoutSource
messageLoggerWithoutSource' LevelInfo = messageInfoLoggerWithoutSource
messageLoggerWithoutSource' LevelWarn = messageWarnLoggerWithoutSource
messageLoggerWithoutSource' LevelError = messageErrorLoggerWithoutSource
messageLoggerWithoutSource' (LevelOther other) = messageOtherLoggerWithoutSource (T.unpack other)

messageDebugLoggerWithoutSource :: LoggerSet -> LogStr -> IO ()
messageDebugLoggerWithoutSource = logWithoutSource "Info"

messageInfoLoggerWithoutSource :: LoggerSet -> LogStr -> IO ()
messageInfoLoggerWithoutSource = logWithoutSource "Info"

messageWarnLoggerWithoutSource :: LoggerSet -> LogStr -> IO ()
messageWarnLoggerWithoutSource = logWithoutSource "Warn"

messageErrorLoggerWithoutSource :: LoggerSet -> LogStr -> IO ()
messageErrorLoggerWithoutSource = logWithoutSource "Error"

messageOtherLoggerWithoutSource :: String -> LoggerSet -> LogStr -> IO ()
messageOtherLoggerWithoutSource level = logWithoutSource level

logWithoutSource :: String -> LoggerSet -> LogStr -> IO ()
logWithoutSource levelText loggerSetValue msg = do
    now <- getZonedTime
    let timestamp = formatTime defaultTimeLocale customTimeFormat now
    let message = BS.unpack (fromLogStr msg)
    let line = timestamp ++ " [" ++ levelText ++ "] " ++ message
    pushLogStrLn loggerSetValue (toLogStr line)
