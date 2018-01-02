from math import sqrt
from random import sample
from collections import defaultdict
from typing import List


def distance(a, b):
    def sqr(a):
        return a * a

    if len(a) != len(b):
        raise ValueError('Vectors have different dimensions')
    return sqrt(sum(map(sqr, (x - y for x, y in zip(a, b)))))


def allocate_clusters(vectors, centroids):
    clusters = defaultdict(list)
    for vector_index, vector in enumerate(vectors):
        centroid = min(centroids, key=lambda x: distance(vector, x))
        clusters[centroids.index(centroid)].append(vector_index)
    return clusters


def get_centroid(vectors, members_indexes):
    component_count = len(vectors[0])
    result = [None] * component_count
    for component in range(component_count):
        result[component] = sum((vectors[i][component] for i in members_indexes)) / len(members_indexes)
    return tuple(result)


def get_first_centroids(vectors: List, clusters_count: int):
    """
    :param vectors:
    :param clusters_count:
    :return: unique centroids (len <= clusters_count)
    """
    centroids = []
    for i in sample(range(len(vectors)), len(vectors)):
        if vectors[i] not in centroids:
            centroids.append(vectors[i])
        if len(centroids) == clusters_count:
            break

    return centroids


def k_means(vectors: List, clusters_count: int, max_iterations: int = 30):
    clusters = None
    centroids = get_first_centroids(vectors, clusters_count)
    for i in range(max_iterations):
        clusters = allocate_clusters(vectors, centroids)
        centroids = list(map(lambda x: get_centroid(vectors, x), clusters.values()))
        old_centroids = set(clusters.keys())
        if old_centroids == set(centroids):
            break
    return clusters
