{-# LANGUAGE OverloadedStrings #-}

module HttpPostHandlerRequestObjectApi
    ( query
    ) where

import qualified Content
import Kbapi (QueryResult(..))
import ApiEnv (ApiEnv, asksKbFilename)
import qualified Location
import Swipl (saveAsMainFile, runSwiplWithTimeout, Stdout(..))
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Maybe (mapMaybe)
import Data.Char (isSpace)
import Data.List (dropWhileEnd)
import Control.Monad.IO.Class (liftIO)

query :: Content.HttpPostHandlerRequestObject -> ApiEnv QueryResult
query (Content.HttpPostHandlerRequestObject _ limit) = do
    kbFilename <- asksKbFilename
    liftIO (putStrLn ("[queryengine][api] HttpPostHandlerRequestObject using kb: " ++ kbFilename))
    program <- liftIO (instantiateTemplate kbFilename limit)
    path <- liftIO (saveAsMainFile program)
    liftIO (putStrLn ("[queryengine][api] SWI-Prolog main file path: " ++ path))
    outputOrTimeout <- liftIO (runSwiplWithTimeout path)
    let matches = decodeMatches outputOrTimeout
    pure (FoundHttpPostHandlerRequestObject Content.FoundHttpPostHandlerRequestObject
        { Content.foundHttpPostHandlerRequestObjectTotal = fromIntegral (length matches)
        , Content.foundHttpPostHandlerRequestObjectMatches = matches
        })

instantiateTemplate :: FilePath -> Word -> IO T.Text
instantiateTemplate kbFilename limit = do
    template <- TIO.readFile "templates/templateHttpPostHandlerRequestObject.pl"
    pure (T.replace "{LIMIT}" (T.pack (show limit))
        (T.replace "{KNOWLEDGE_BASE}" (T.pack kbFilename) template))

decodeMatches :: Maybe (Stdout, a) -> [ Content.FoundHttpPostHandlerRequestObjectMatch ]
decodeMatches (Just (Stdout out, _)) = mapMaybe decodeMatch (extractTupleTerms out)
decodeMatches _ = []

decodeMatch :: String -> Maybe Content.FoundHttpPostHandlerRequestObjectMatch
decodeMatch line = do
    (_, request, url) <- splitTriple line
    pure Content.FoundHttpPostHandlerRequestObjectMatch
        { Content.foundHttpPostHandlerRequestObjectMatchLocation = toLocation request
        , Content.foundHttpPostHandlerRequestObjectMatchUrl = url
        }

toLocation :: String -> Location.Location
toLocation raw = Location.Location
    { Location.filename = raw
    , Location.lineStart = 0
    , Location.lineEnd = 0
    , Location.colStart = 0
    , Location.colEnd = 0
    }

splitTriple :: String -> Maybe (String, String, String)
splitTriple line = do
    inner <- stripOuterParens (trim line)
    (firstCommaIdx, secondCommaIdx) <- findFirstTwoTopLevelCommas inner
    let first = trim (take firstCommaIdx inner)
    let second = trim (take (secondCommaIdx - firstCommaIdx - 1) (drop (firstCommaIdx + 1) inner))
    let third = trim (drop (secondCommaIdx + 1) inner)
    pure (first, second, third)

findFirstTwoTopLevelCommas :: String -> Maybe (Int, Int)
findFirstTwoTopLevelCommas = go 0 0 False False []
  where
    go :: Int -> Int -> Bool -> Bool -> [Int] -> String -> Maybe (Int, Int)
    go _ _ _ _ indices [] = case indices of
        (firstIdx:secondIdx:_) -> Just (firstIdx, secondIdx)
        _ -> Nothing
    go idx depth inSingleQuote inDoubleQuote indices (ch:rest)
        | ch == '\'' && not inDoubleQuote = go (idx + 1) depth (not inSingleQuote) inDoubleQuote indices rest
        | ch == '"' && not inSingleQuote = go (idx + 1) depth inSingleQuote (not inDoubleQuote) indices rest
        | inSingleQuote || inDoubleQuote = go (idx + 1) depth inSingleQuote inDoubleQuote indices rest
        | ch == '(' = go (idx + 1) (depth + 1) inSingleQuote inDoubleQuote indices rest
        | ch == ')' = go (idx + 1) (max 0 (depth - 1)) inSingleQuote inDoubleQuote indices rest
        | ch == ',' && depth == 0 && length indices < 2 = go (idx + 1) depth inSingleQuote inDoubleQuote (indices ++ [idx]) rest
        | otherwise = go (idx + 1) depth inSingleQuote inDoubleQuote indices rest

stripOuterParens :: String -> Maybe String
stripOuterParens ('(' : rest) = case reverse rest of
    ')' : innerRev -> Just (reverse innerRev)
    _ -> Nothing
stripOuterParens _ = Nothing

trim :: String -> String
trim = dropWhile isSpace . dropWhileEnd isSpace

extractTupleTerms :: String -> [ String ]
extractTupleTerms = reverse . finalize . foldl step ([], Nothing, 0, False, False)
  where
    step :: ([ String ], Maybe String, Int, Bool, Bool) -> Char -> ([ String ], Maybe String, Int, Bool, Bool)
    step (acc, current, depth, inSingleQuote, inDoubleQuote) ch
        | ch == '\'' && not inDoubleQuote =
            (acc, append ch current, depth, not inSingleQuote, inDoubleQuote)
        | ch == '"' && not inSingleQuote =
            (acc, append ch current, depth, inSingleQuote, not inDoubleQuote)
        | inSingleQuote || inDoubleQuote =
            (acc, append ch current, depth, inSingleQuote, inDoubleQuote)
        | ch == '(' =
            let current' = case current of
                    Nothing -> Just ""
                    _ -> current
            in (acc, append ch current', depth + 1, inSingleQuote, inDoubleQuote)
        | ch == ')' =
            case current of
                Nothing -> (acc, Nothing, 0, inSingleQuote, inDoubleQuote)
                Just buf ->
                    let buf' = buf ++ [ ch ]
                        depth' = max 0 (depth - 1)
                    in if depth' == 0
                        then (buf' : acc, Nothing, 0, inSingleQuote, inDoubleQuote)
                        else (acc, Just buf', depth', inSingleQuote, inDoubleQuote)
        | otherwise =
            (acc, append ch current, depth, inSingleQuote, inDoubleQuote)

    append :: Char -> Maybe String -> Maybe String
    append _ Nothing = Nothing
    append ch (Just xs) = Just (xs ++ [ ch ])

    finalize :: ([ String ], Maybe String, Int, Bool, Bool) -> [ String ]
    finalize (acc, Just buf, _, _, _) = buf : acc
    finalize (acc, Nothing, _, _, _) = acc
