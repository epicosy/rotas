import argparse
import uvicorn

from rotas import create_api
from arepo.db import DatabaseConnection
from rotas.utils import get_allowed_origins


def main():
    parser = argparse.ArgumentParser("CLI for the API")
    parser.add_argument('-u', '--uri', help='Database URI', required=True)

    subparsers = parser.add_subparsers(dest='subparser')
    serve_parser = subparsers.add_parser('serve', help='Launch API (ASGI server)')

    serve_parser.add_argument('-p', '--port', help='Port for server.', type=int, default=8000)
    serve_parser.add_argument('-a', '--address', help='IPv4 host address for server.', type=str,
                              default="localhost")
    serve_parser.add_argument('-d', '--debug', help='Debug mode for server.', action='store_true')

    args = parser.parse_args()

    db_con = DatabaseConnection(args.uri)
    session = db_con.get_session(scoped=True)

    if args.subparser == 'serve':
        # TODO: fix this, for some reason none of the origins work, only when the origin is hardcoded
        # allowed_origins = get_allowed_origins()
        # allowed_origins.append(f"http://{args.address}:\d+")
        # print(f"Allowed origins: {allowed_origins}")

        api = create_api(debug=args.debug)
        uvicorn.run(api, host=args.address, port=args.port)
