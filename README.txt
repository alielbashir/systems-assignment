While writing this project, I gained a lot of knowledge in both javascript and golang.
Learning go was on my mind for a long time, so this project was a nice way to get into
that. The simplicity, ease of learning, as well as it's community made it a nice
experience to learn. For the frontend I used react - which I've never done  before - and
throughout that I got a better understanding of frontend rendering and the importance of
immutable objects.

The most difficult part of this project was writing the auth and verify endpoints for the
systems assignment, due to the golang-jwt library. Due to the lack of examples done with
the RS256 algorithm. Specifically, the return type of the keyfunc in the Parse function was
a point of confusion for me, since some examples return simply a string with the jwt secret.
After some research, and inspecting the source code and tests for the library, I found that
the return type must be an RSA Public key.

I attempted extras