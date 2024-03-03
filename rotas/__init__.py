import pkg_resources

__version__ = pkg_resources.get_distribution('rotas').version

from starlette.routing import Route
from starlette.applications import Starlette
from starlette.responses import JSONResponse

from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette_graphene3 import GraphQLApp, make_graphiql_handler

from rotas.schema import schema


async def index(request):
    return JSONResponse({"message": f"Rotas ({__version__}) API"})


def create_api(debug: bool = False, allowed_origins: list = None):
    middleware = [
        Middleware(CORSMiddleware,
                   allow_origins=allowed_origins if allowed_origins else ["*"],
                   allow_credentials=True,
                   allow_methods=["*"],
                   allow_headers=["*"])
    ]

    app = Starlette(debug=debug, routes=[Route('/', index)], middleware=middleware)
    app.mount("/graphql", GraphQLApp(schema, on_get=make_graphiql_handler()))  # Graphiql IDE

    return app
