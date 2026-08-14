{-# LANGUAGE OverloadedStrings #-}

module UnauthenticatedHttpPostHandlerRequestObjectApi
    ( query
    ) where

import qualified Content
import Kbapi (QueryResult(..))
import Kbgen (restoreloc)
import ApiEnv (ApiEnv, asksKbFilename)
import Swipl (saveAsMainFile, runSwiplWithTimeout, Stdout(..))
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Maybe (mapMaybe)
import Data.Char (isSpace)
import Data.List (stripPrefix)
import Data.List (dropWhileEnd)
import Control.Monad.IO.Class (liftIO)

query :: Content.UnauthenticatedHttpPostHandlerRequestObject -> ApiEnv QueryResult
query (Content.UnauthenticatedHttpPostHandlerRequestObject _ limit) = do
    kbFilename <- asksKbFilename
    liftIO (putStrLn ("[queryengine][api] UnauthenticatedHttpPostHandlerRequestObject using kb: " ++ kbFilename))
    program <- liftIO (instantiateTemplate kbFilename limit)
    path <- liftIO (saveAsMainFile program)
    liftIO (putStrLn ("[queryengine][api] SWI-Prolog main file path: " ++ path))
    outputOrTimeout <- liftIO (runSwiplWithTimeout path)
    let matches = decodeMatches outputOrTimeout
    pure (FoundUnauthenticatedHttpPostHandlerRequestObject Content.FoundUnauthenticatedHttpPostHandlerRequestObject
        { Content.foundUnauthenticatedHttpPostHandlerRequestObjectTotal = fromIntegral (length matches)
        , Content.foundUnauthenticatedHttpPostHandlerRequestObjectMatches = matches
        })

instantiateTemplate :: FilePath -> Word -> IO T.Text
instantiateTemplate kbFilename limit = do
    template <- TIO.readFile "templates/templateUnauthenticatedHttpPostHandlerRequestObject.pl"
    pure (T.replace "{LIMIT}" (T.pack (show limit))
        (T.replace "{KNOWLEDGE_BASE}" (T.pack kbFilename) template))

decodeMatches :: Maybe (Stdout, a) -> [ Content.FoundHttpPostHandlerRequestObjectMatch ]
decodeMatches (Just (Stdout out, _)) = mapMaybe decodeMatch (extractMatchBlocks out)
decodeMatches _ = []

decodeMatch :: [String] -> Maybe Content.FoundHttpPostHandlerRequestObjectMatch
decodeMatch rawLines = do
    (handlerLine:requestLine:urlLine:[]) <- Just (map trim (filter (not . all isSpace) rawLines))
    handler <- parseTaggedTerm "PostHandler" handlerLine
    request <- parseTaggedTerm "Request" requestLine
    url <- parseTaggedTerm "Url" urlLine
    handlerLoc <- restoreloc handler
    loc <- restoreloc request
    pure Content.FoundHttpPostHandlerRequestObjectMatch
        { Content.foundHttpPostHandlerLocation = handlerLoc
        , Content.foundHttpPostHandlerRequestObjectLocation = loc
        , Content.foundHttpPostHandlerRequestObjectMatchUrl = url
        }

parseTaggedTerm :: String -> String -> Maybe String
parseTaggedTerm tag line = do
    inner <- stripPrefix (tag ++ "(") (trim line)
    stripSuffix ")" inner

trim :: String -> String
trim = dropWhile isSpace . dropWhileEnd isSpace

stripSuffix :: String -> String -> Maybe String
stripSuffix suffix value =
    if suffix == reverse (take (length suffix) (reverse value))
        then Just (take (length value - length suffix) value)
        else Nothing

extractMatchBlocks :: String -> [[String]]
extractMatchBlocks = reverse . finalize . foldl step ([], []) . lines
  where
    step :: ([[String]], [String]) -> String -> ([[String]], [String])
    step (blocks, current) line
        | all isSpace line =
            if null current
                then (blocks, current)
                else (reverse current : blocks, [])
        | otherwise = (blocks, line : current)

    finalize :: ([[String]], [String]) -> [[String]]
    finalize (blocks, []) = blocks
    finalize (blocks, current) = reverse current : blocks
