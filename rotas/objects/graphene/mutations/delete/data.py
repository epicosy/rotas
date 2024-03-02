import graphene
from graphql import GraphQLError


from rotas.objects.sqlalchemy.data import Dataset, DatasetVulnerability


class RemoveDataset(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int):

        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        # remove all dataset vulnerabilities
        # TODO: replace this code with the one below to remove all dataset vulnerabilities
        dataset_vulnerabilities = DatasetVulnerability.get_query(info).filter_by(dataset_id=id).all()

        for dv in dataset_vulnerabilities:
            dv.remove()

        # remove dataset
        dataset.remove()

        return RemoveDataset(dataset=dataset)


class RemoveDatasetVulnerabilities(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int):
        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        dataset_vulnerabilities = DatasetVulnerability.get_query(info).filter_by(dataset_id=id).all()

        for dv in dataset_vulnerabilities:
            dv.remove()

        return RemoveDatasetVulnerabilities(dataset=dataset)
