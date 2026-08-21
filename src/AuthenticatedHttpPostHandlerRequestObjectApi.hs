{-# LANGUAGE OverloadedStrings #-}

module AuthenticatedHttpPostHandlerRequestObjectApi
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

query :: Content.AuthenticatedHttpPostHandlerRequestObject -> ApiEnv QueryResult
query (Content.AuthenticatedHttpPostHandlerRequestObject _ limit) = do
    kbFilename <- asksKbFilename
    liftIO (putStrLn ("[queryengine][api] AuthenticatedHttpPostHandlerRequestObject using kb: " ++ kbFilename))
    program <- liftIO (instantiateTemplate kbFilename limit)
    path <- liftIO (saveAsMainFile program)
    liftIO (putStrLn ("[queryengine][api] SWI-Prolog main file path: " ++ path))
    outputOrTimeout <- liftIO (runSwiplWithTimeout path)
    let matches = decodeMatches outputOrTimeout
    pure (FoundAuthenticatedHttpPostHandlerRequestObject Content.FoundAuthenticatedHttpPostHandlerRequestObject
        { Content.foundAuthenticatedHttpPostHandlerRequestObjectTotal = fromIntegral (length matches)
        , Content.foundAuthenticatedHttpPostHandlerRequestObjectMatches = matches
        })

instantiateTemplate :: FilePath -> Word -> IO T.Text
instantiateTemplate kbFilename limit = do
    template <- TIO.readFile "templates/templateAuthenticatedHttpPostHandlerRequestObject.pl"
    pure (T.replace "{LIMIT}" (T.pack (show limit))
        (T.replace "{KNOWLEDGE_BASE}" (T.pack kbFilename) template))

decodeMatches :: Maybe (Stdout, a) -> [ Content.FoundAuthenticatedHttpPostHandlerRequestObjectMatch ]
decodeMatches (Just (Stdout out, _)) = mapMaybe decodeMatch (extractMatchBlocks out)
decodeMatches _ = []

-- | Parses one 5-line block emitted by
-- `templateAuthenticatedHttpPostHandlerRequestObject.pl`:
--
--     PostHandler(<location-atom>)
--     Request(<location-atom>)
--     Url(<url-atom-or-string>)
--     AuthFuncName(<name-atom>)
--     HeaderKey(<key-atom>)
--
-- The auth-function name and header-key strings come through Prolog's
-- `~q` formatter, so bare atoms are unquoted and atoms with special
-- chars (hyphens, dots) come wrapped in single quotes — hence the
-- `unquotePrologAtom` step.
decodeMatch :: [String] -> Maybe Content.FoundAuthenticatedHttpPostHandlerRequestObjectMatch
decodeMatch rawLines = do
    (handlerLine:requestLine:urlLine:authFuncLine:headerKeyLine:[]) <- Just (map trim (filter (not . all isSpace) rawLines))
    handler <- parseTaggedTerm "PostHandler" handlerLine
    request <- parseTaggedTerm "Request" requestLine
    url <- parseTaggedTerm "Url" urlLine
    authFuncName <- parseTaggedTerm "AuthFuncName" authFuncLine
    headerKey <- parseTaggedTerm "HeaderKey" headerKeyLine
    handlerLoc <- restoreloc handler
    loc <- restoreloc request
    pure Content.FoundAuthenticatedHttpPostHandlerRequestObjectMatch
        { Content.foundAuthenticatedHttpPostHandlerLocation = handlerLoc
        , Content.foundAuthenticatedHttpPostHandlerRequestObjectLocation = loc
        , Content.foundAuthenticatedHttpPostHandlerRequestObjectMatchUrl = unquotePrologAtom url
        , Content.foundAuthenticatedHttpPostHandlerAuthenticatingFunctionName = unquotePrologAtom authFuncName
        , Content.foundAuthenticatedHttpPostHandlerHeaderKeyName = unquotePrologAtom headerKey
        }

parseTaggedTerm :: String -> String -> Maybe String
parseTaggedTerm tag line = do
    inner <- stripPrefix (tag ++ "(") (trim line)
    stripSuffix ")" inner

-- | Strips the single-quote wrapper Prolog's `~q` adds around atoms
-- with characters that would otherwise need quoting (hyphens, dots,
-- slashes, ...). Leaves already-bare atoms untouched.
unquotePrologAtom :: String -> String
unquotePrologAtom s = case s of
    ('\'':rest) | not (null rest) && last rest == '\'' -> init rest
    _ -> s

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
