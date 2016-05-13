module MyMod.HaskellLike exposing (..)

($) : (a -> b) -> a -> b
($) = (<|)

(.) : (b -> c) -> (a -> b) -> (a -> c)
(.) = (<<)

zipWith : (a -> b -> c) -> List a -> List b  -> List c
zipWith = List.map2

foldl : (a -> b -> a) -> a -> List b -> a
foldl f e xs = List.foldl (flip f) e xs
