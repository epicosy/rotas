from rotas.schema import schema
from arepo.db import DatabaseConnection


def main():
    query_cwes = '''
        query {
          cwes {
            id,
            name
          }
        }
    '''

    db_con = DatabaseConnection('postgresql://user1:user123@localhost:5432/test')
    db_session = db_con.get_session()

    result = schema.execute(query_cwes, context_value={'session': db_session})

    print(result)
