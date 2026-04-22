{-# LANGUAGE OverloadedStrings #-}

module ConstStringsMatchingApi
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

query :: Content.ConstStringsMatching -> ApiEnv QueryResult
query (Content.ConstStringsMatching regex limit) = do
    kbFilename <- asksKbFilename
    liftIO (putStrLn ("[queryengine][api] ConstStringsMatching using kb: " ++ kbFilename))
    program <- liftIO (instantiateTemplate kbFilename regex limit)
    path <- liftIO (saveAsMainFile program)
    liftIO (putStrLn ("[queryengine][api] SWI-Prolog main file path: " ++ path))
    outputOrTimeout <- liftIO (runSwiplWithTimeout path)
    let matches = decodeConstStringMatches outputOrTimeout
    pure (FoundConstStringsMatching Content.FoundConstStringsMatching { Content.foundConstStringsMatchingThisRegex = regex, Content.foundConstStringsMatchesTotal = fromIntegral (length matches), Content.foundConstStringsMatches = matches })

instantiateTemplate :: FilePath -> String -> Word -> IO T.Text
instantiateTemplate kbFilename regex limit = do
    template <- TIO.readFile "templates/templateConstStringsMatching.pl"
    pure (T.replace "{LIMIT}" (T.pack (show limit))
        (T.replace "{REGEX}" (T.pack regex)
            (T.replace "{KNOWLEDGE_BASE}" (T.pack kbFilename) template)))

decodeConstStringMatches :: Maybe (Stdout, a) -> [ Content.FoundConstStringMatch ]
decodeConstStringMatches (Just (Stdout out, _)) = mapMaybe decodeConstStringMatch (extractTupleTerms out)
decodeConstStringMatches _ = []

decodeConstStringMatch :: String -> Maybe Content.FoundConstStringMatch
decodeConstStringMatch line = do
    (location, value) <- splitEdge line
    pure Content.FoundConstStringMatch
        { Content.foundConstStringMatchLocation = toLocation location
        , Content.foundConstStringMatchValue = value
        }

toLocation :: String -> Location.Location
toLocation raw = Location.Location
    { Location.filename = raw
    , Location.lineStart = 0
    , Location.lineEnd = 0
    , Location.colStart = 0
    , Location.colEnd = 0
    }

splitEdge :: String -> Maybe (String, String)
splitEdge line = do
    inner <- stripOuterParens (trim line)
    separatorIdx <- findTopLevelComma inner
    let location = trim (take separatorIdx inner)
    let value = trim (drop (separatorIdx + 1) inner)
    pure (location, value)

stripOuterParens :: String -> Maybe String
stripOuterParens ('(' : rest) = case reverse rest of
    ')' : innerRev -> Just (reverse innerRev)
    _ -> Nothing
stripOuterParens _ = Nothing

findTopLevelComma :: String -> Maybe Int
findTopLevelComma = go 0 0 False False
  where
    go :: Int -> Int -> Bool -> Bool -> String -> Maybe Int
    go _ _ _ _ [] = Nothing
    go idx depth inSingleQuote inDoubleQuote (ch:rest)
        | ch == '\'' && not inDoubleQuote = go (idx + 1) depth (not inSingleQuote) inDoubleQuote rest
        | ch == '"' && not inSingleQuote = go (idx + 1) depth inSingleQuote (not inDoubleQuote) rest
        | inSingleQuote || inDoubleQuote = go (idx + 1) depth inSingleQuote inDoubleQuote rest
        | ch == '(' = go (idx + 1) (depth + 1) inSingleQuote inDoubleQuote rest
        | ch == ')' = go (idx + 1) (max 0 (depth - 1)) inSingleQuote inDoubleQuote rest
        | ch == ',' && depth == 0 = Just idx
        | otherwise = go (idx + 1) depth inSingleQuote inDoubleQuote rest

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
