module ExampleTest exposing (..)

import ElmTest exposing (..)

add : Int -> Int -> Int
add = (+)

tests : ElmTest.Test
tests =
  suite "A Test Example" [
    test "[add] 1 + 1 = 1?" (ElmTest.assertEqual (add 1 2) 3)
  ]
