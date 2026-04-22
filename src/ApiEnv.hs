module ApiEnv
    ( ApiConfig(..)
    , ApiEnv
    , runApiEnv
    , asksKbFilename
    ) where

import Control.Monad.Reader (ReaderT, asks, runReaderT)

data ApiConfig
    = ApiConfig
    {
        apiEnvKbFilename :: FilePath
    }

type ApiEnv = ReaderT ApiConfig IO

runApiEnv :: ApiConfig -> ApiEnv a -> IO a
runApiEnv = flip runReaderT

asksKbFilename :: ApiEnv FilePath
asksKbFilename = asks apiEnvKbFilename
