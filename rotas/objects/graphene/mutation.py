import graphene

from typing import List
from graphene import ObjectType
from graphql import GraphQLError

from rotas.objects.sqlalchemy.data import (Dataset, DatasetModel, DatasetVulnerability, DatasetVulnerabilityModel,
                                           Profile, ProfileCWE)

from rotas.objects.sqlalchemy.git import (CommitModel, Repository, RepositoryProductType, RepositoryProductTypeModel)

from rotas.objects.sqlalchemy.common.vulnerability import Vulnerability, VulnerabilityModel
from rotas.objects.sqlalchemy.common.platform import ProductType


# from sator.utils.misc import get_file_content_from_url, get_digest, JavaMethodExtractor
# from rotas.objects.sqlalchemy.code import Line, LineModel, Function, FunctionModel

from rotas.objects.graphene.queries.helpers import profiling_vuln_query, profiling_commit_query


class CreateProfile(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        has_code = graphene.Boolean(required=False)
        has_exploit = graphene.Boolean(required=False)
        has_advisory = graphene.Boolean(required=False)
        start_year = graphene.Int(required=False)
        end_year = graphene.Int(required=False)
        start_score = graphene.Float(required=False)
        end_score = graphene.Float(required=False)
        min_changes = graphene.Int(required=False)
        max_changes = graphene.Int(required=False)
        min_files = graphene.Int(required=False)
        max_files = graphene.Int(required=False)
        extensions = graphene.List(graphene.String, required=False)
        cwe_ids = graphene.List(graphene.Int, required=False)

    profile = graphene.Field(lambda: Profile)

    def mutate(self, info, name: str, start_year: int = 1987, end_year: int = None, cwe_ids: List[int] = None,
               start_score: float = 0, end_score: float = 10, has_code: bool = False, has_exploit: bool = False,
               has_advisory: bool = False, min_changes: int = 0, max_changes: int = None, min_files: int = 0,
               max_files: int = None, extensions: List[str] = None):

        if Profile.get_query(info).filter_by(name=name).first():
            raise GraphQLError(f"Profile with name {name} already exists")

        if not cwe_ids:
            cwe_ids = []

        if not extensions:
            extension = None
        else:
            # TODO: change this to cover for multiple extensions
            extension = extensions[0]

        profile = Profile(name=name, start_year=start_year, end_year=end_year, start_score=start_score,
                          end_score=end_score, min_changes=min_changes, max_changes=max_changes, min_files=min_files,
                          max_files=max_files, has_code=has_code, has_exploit=has_exploit, has_advisory=has_advisory,
                          extension=extension)
        profile.save()

        for cwe_id in cwe_ids:
            profile_cwe = ProfileCWE(profile_id=profile.id, cwe_id=cwe_id)
            profile_cwe.save()

        # TODO: check if we need to add all fields to the profile object
        profile = Profile(id=profile.id, name=name)

        return CreateProfile(profile=profile)


class CreateDataset(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        description = graphene.String(required=False)
        profile_id = graphene.Int(required=False)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, name, description=None, profile_id=None):

        if Dataset.get_query(info).filter_by(name=name).first():
            raise GraphQLError(f"Dataset with name {name} already exists")

        cve_ids = []

        if profile_id:
            profile = Profile.get_query(info).filter_by(id=profile_id).first()

            if not profile:
                raise GraphQLError(f"Profile with id {profile_id} does not exist")

            # get cwe_ids from the profile
            cwe_ids = [r.cwe_id for r in ProfileCWE.get_query(info).filter_by(profile_id=profile_id).all()]
            extensions = [profile.extension] if profile.extension else None
            vuln_query = profiling_vuln_query(info, start_year=profile.start_year, end_year=profile.end_year,
                                              start_score=profile.start_score, end_score=profile.end_score,
                                              cwe_ids=cwe_ids, has_exploit=profile.has_exploit,
                                              has_advisory=profile.has_advisory)
            commit_query = profiling_commit_query(info, vuln_query, min_changes=profile.min_changes,
                                                  max_changes=profile.max_changes, min_files=profile.min_files,
                                                  max_files=profile.max_files, extensions=extensions)

            # get distinct cve_ids from commit_query
            cve_ids = [c.vulnerability_id for c in commit_query.with_entities(CommitModel.vulnerability_id).distinct().all()]

        dataset = DatasetModel(name=name, description=description)
        dataset.save()

        for cve_id in cve_ids:
            dataset_vulnerability = DatasetVulnerabilityModel(dataset_id=dataset.id, vulnerability_id=cve_id)
            dataset_vulnerability.save()

        dataset = Dataset(id=dataset.id, name=name, description=description)

        return CreateDataset(dataset=dataset)


class EditDataset(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)
        name = graphene.String(required=False)
        description = graphene.String(required=False)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int, name: str, description: str):
        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        if name and name != dataset.name:
            # check if name does not exist in the dataset table
            if Dataset.get_query(info).filter_by(name=name).first():
                raise GraphQLError(f"Dataset with name {name} already exists")

            # check the length of the dataset name is not more than 255 characters
            if len(name) > 255:
                raise GraphQLError(f"Dataset name cannot be more than 255 characters")

            dataset.name = name

        if description:
            # check if the length of the description is not more than 1000 characters
            if len(description) > 1000:
                raise GraphQLError(f"Dataset description cannot be more than 1000 characters")

            dataset.description = description

        dataset.save()

        return EditDataset(dataset=dataset)


class RemoveDataset(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int):

        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        # remove all dataset vulnerabilities
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


class AddDatasetVulnerabilities(graphene.Mutation):
    class Arguments:
        vulnerability_ids = graphene.List(graphene.String, required=True)
        dataset_id = graphene.Int(required=True)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, vulnerability_ids: list, dataset_id: int):
        if not vulnerability_ids:
            raise GraphQLError("No vulnerabilities provided")

        if not dataset_id:
            raise GraphQLError("No dataset id provided")

        dataset = Dataset.get_query(info).filter_by(id=dataset_id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {dataset_id} does not exist")

        dataset_vulnerabilities = DatasetVulnerability.get_query(info).filter_by(dataset_id=dataset_id).all()
        dataset_vulnerability_ids = [dv.vulnerability_id for dv in dataset_vulnerabilities]

        # the following checks if vulnerabilities exist in the vulnerability table
        vulns = Vulnerability.get_query(info).filter(VulnerabilityModel.id.in_(vulnerability_ids)).all()

        for vuln in vulns:
            if vuln.id not in dataset_vulnerability_ids:
                dv = DatasetVulnerabilityModel(dataset_id=dataset_id, vulnerability_id=vuln.id)
                dv.save()

        # return error message for the rest of vulnerabilities that were not added to the dataset
        if len(vulnerability_ids) != len(vulns):
            vuln_ids = [v.id for v in vulns]
            for v in vulnerability_ids:
                if v not in vuln_ids:
                    raise GraphQLError(f"Vulnerability with id {v} does not exist")

        return AddDatasetVulnerabilities(dataset=dataset)


# TODO: this has functionality that is not part of this project
"""
class LoadFile(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)

    file = graphene.Field(lambda: CommitFile)

    def mutate(self, info, id: str):
        file = CommitFile.get_query(info).filter_by(id=id).first()

        if not file:
            raise GraphQLError(f"File with id {id} does not exist")

        try:
            content = get_file_content_from_url(file.raw_url)
        except Exception as e:
            raise GraphQLError(f"Error loading file content from url {file.raw_url}: {e}")

        lines = Line.get_query(info).filter_by(commit_file_id=file.id).all()

        if not lines:
            line_records = []

            for i, line in enumerate(content.split("\n"), 1):
                line_id = get_digest(f"{file.id}-{i}")
                line_records.append(LineModel(id=line_id, number=i, content=line, commit_file_id=file.id))

            LineModel.add_all(line_records)

        return LoadFile(file=file)
"""

# TODO: this has functionality that is not part of this project
"""
class ExtractFunctions(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)

    file = graphene.Field(lambda: CommitFile)

    def mutate(self, info, id: str):
        file = CommitFile.get_query(info).filter_by(id=id).first()

        if not file:
            raise GraphQLError(f"File with id {id} does not exist")

        if file.extension != ".java":
            raise GraphQLError(f"File with id {id} is not within available languages: [Java]")

        functions = Function.get_query(info).filter_by(commit_file_id=file.id).order_by(FunctionModel.start).all()

        if not functions:

            lines = Line.get_query(info).filter_by(commit_file_id=file.id).all()

            if not lines:
                raise GraphQLError(f"File with id {id} has not been previously loaded")

            try:
                jve = JavaMethodExtractor(code_lines=[l.content for l in lines])
            except Exception as e:
                raise GraphQLError(f"Failed to extract methods: {str(e)}")

            for method in jve.methods:
                functions.append(FunctionModel(id=get_digest(f"{file.id}-{method.name}-{method.start_line}"),
                                               name=method.name, start_line=method.start_line, start_col=method.start_col,
                                               end_line=method.end_line, end_col=method.end_col, commit_file_id=file.id,
                                               size=len(method))
                                 )

            FunctionModel.add_all(functions)

        return ExtractFunctions(file=file)
"""


class RepositorySoftwareType(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)
        software_type_id = graphene.Int(required=True)

    repository = graphene.Field(lambda: Repository)

    def mutate(self, info, id: str, software_type_id: int):
        repository = Repository.get_query(info).filter_by(id=id).first()

        if not repository:
            raise GraphQLError(f"Repository with id {id} does not exist")

        software_type = ProductType.get_query(info).filter_by(id=software_type_id).first()

        if not software_type:
            raise GraphQLError(f"Software type with id {software_type_id} does not exist")

        repository_product_type = RepositoryProductType.get_query(info).filter_by(repository_id=id).first()

        if repository_product_type:
            repository_product_type.product_type_id = software_type_id
        else:
            repository_product_type = RepositoryProductTypeModel(repository_id=id, product_type_id=software_type_id)

        repository_product_type.save()
        repository.software_type = software_type.name

        return RepositorySoftwareType(repository=repository)


class Mutation(ObjectType):
    create_dataset = CreateDataset.Field()
    create_profile = CreateProfile.Field()
    remove_dataset = RemoveDataset.Field()
    remove_dataset_vulnerabilities = RemoveDatasetVulnerabilities.Field()
    add_vulnerabilities_to_dataset = AddDatasetVulnerabilities.Field()
    edit_dataset = EditDataset.Field()
    repository_software_type = RepositorySoftwareType.Field()
    # load_file = LoadFile.Field()
