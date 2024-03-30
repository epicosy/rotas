import graphene

from typing import List
from graphql import GraphQLError

from arepo.models.common.vulnerability import VulnerabilityModel
from arepo.models.vcs.core import CommitModel
from arepo.models.data import ProfileModel, ProfileCWEModel, DatasetVulnerabilityModel, DatasetModel

from rotas.objects.sqlalchemy.common.vulnerability import Vulnerability
from rotas.objects.sqlalchemy.data import Profile, ProfileCWE, Dataset, DatasetVulnerability

#from rotas.objects.graphene.helpers.query import profiling_vuln_query, profiling_commit_query


class CreateProfile(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        has_code = graphene.Boolean(required=False)
        has_exploit = graphene.Boolean(required=False)
        has_advisory = graphene.Boolean(required=False)
        single_commit = graphene.Boolean(required=False)
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
               has_advisory: bool = False, single_commit: bool = False, min_changes: int = 0, max_changes: int = None,
               min_files: int = 0, max_files: int = None, extensions: List[str] = None):

        if Profile.get_query(info).filter_by(name=name).first():
            raise GraphQLError(f"Profile with name {name} already exists")

        if not cwe_ids:
            cwe_ids = []

        if not extensions:
            extension = None
        else:
            # TODO: change this to cover for multiple extensions
            extension = extensions[0]

        profile = ProfileModel(name=name, start_year=start_year, end_year=end_year, start_score=start_score,
                               end_score=end_score, min_changes=min_changes, max_changes=max_changes,
                               min_files=min_files, max_files=max_files, has_code=has_code, has_exploit=has_exploit,
                               has_advisory=has_advisory, single_commit=single_commit, extension=extension)
        profile.save()

        for cwe_id in cwe_ids:
            profile_cwe = ProfileCWEModel(profile_id=profile.id, cwe_id=cwe_id)
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

            # TODO: fix this
            # get cwe_ids from the profile
            cwe_ids = [r.cwe_id for r in ProfileCWE.get_query(info).filter_by(profile_id=profile_id).all()]
            extensions = [profile.extension] if profile.extension else None
            #vuln_query = profiling_vuln_query(info, start_year=profile.start_year, end_year=profile.end_year,
            #                                  start_score=profile.start_score, end_score=profile.end_score,
            #                                  cwe_ids=cwe_ids, has_exploit=profile.has_exploit,
            #                                  has_advisory=profile.has_advisory)
            #commit_query = profiling_commit_query(info, vuln_query, single_commit=profile.single_commit,
            #                                      min_changes=profile.min_changes,
            #                                      max_changes=profile.max_changes, min_files=profile.min_files,
            #                                      max_files=profile.max_files, extensions=extensions)

            # get distinct cve_ids from commit_query
            #cve_ids = [c.vulnerability_id for c in commit_query.with_entities(CommitModel.vulnerability_id).distinct().all()]

        dataset = DatasetModel(name=name, description=description)
        dataset.save()

        for cve_id in cve_ids:
            dataset_vulnerability = DatasetVulnerabilityModel(dataset_id=dataset.id, vulnerability_id=cve_id)
            dataset_vulnerability.save()

        dataset = Dataset(id=dataset.id, name=name, description=description)

        return CreateDataset(dataset=dataset)


class AddDatasetVulnerabilities(graphene.Mutation):
    class Arguments:
        vulnerability_ids = graphene.List(graphene.String, required=True)
        dataset_id = graphene.ID(required=True)

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
