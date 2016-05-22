module Components.Update.Update exposing (
  Message(..), Page(..), Action(..),
  update, makeLocalMessage
  )

import Html exposing (Html, Attribute, div)
import Html.Attributes exposing (..)
import Html.Events exposing (onClick)

import Components.Model.Model as M

type Page = Home | RegisterNewUser | UserProfile

type GlobalEvent = PageTransition Page | NoGlobalEvent

type LocalEvent = LocalEvent {name: String, value: String} | NoLocalEvent

type Action = GlobalAction GlobalEvent | LocalAction LocalEvent

-- UPDATE
type Message = SomeMessage Action | NoMessage

-- noMessageAttr : Html Message
-- noMessageAttr = input [onClick NoMessage] 

-- noMessageHtml : Html a -> Html a
-- noMessageHtml element = div [] [element, noMessageAttr]

update : Message -> M.Model -> M.Model
update msg model =
  case msg of
    SomeMessage (GlobalAction event) -> updateOnGlobal event model
    SomeMessage (LocalAction event) -> updateOnLocal event model
    NoMessage                     -> model

-- TODO
updateOnGlobal : GlobalEvent -> M.Model -> M.Model
updateOnGlobal _ model = model

-- TODO
updateOnLocal : LocalEvent -> M.Model -> M.Model
updateOnLocal event (M.Model v) =
  case event of
    LocalEvent _ -> M.Model <| v + 1
    NoLocalEvent -> M.Model v

makeLocalMessage : String -> String -> Message
makeLocalMessage name value = SomeMessage <| LocalAction <| LocalEvent <| {name = name, value = value}
