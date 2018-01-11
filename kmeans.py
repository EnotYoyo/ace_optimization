from math import sqrt
from random import sample
from collections import defaultdict
from typing import List
import numpy as np


def distance(a, b):
    if len(a) != len(b):
        raise ValueError('Vectors have different dimensions')
    return sqrt(np.sum((a - b) ** 2))


def allocate_clusters(vectors, centroids):
    clusters = defaultdict(list)
    for vector_index, vector in enumerate(vectors):
        centroid = min(centroids, key=lambda x: distance(vector, x))
        clusters[centroids.tolist().index(centroid.tolist())].append(vector_index)
    return clusters


def get_centroid(vectors, members_indexes):
    return np.sum(vectors[i] for i in members_indexes) / len(members_indexes)


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


def has_converged(new_centroids, old_centroids):
    return set(tuple(x.tolist()) for x in new_centroids) == set(old_centroids.keys())


def k_means(vectors: List, clusters_count: int, max_iterations: int = 30):
    clusters = None
    _centroids = get_first_centroids(vectors, clusters_count)
    _vectors = np.array(vectors)
    for i in range(max_iterations):
        clusters = allocate_clusters(_vectors, np.array(_centroids))
        _centroids = list(map(lambda x: get_centroid(_vectors, x), clusters.values()))
        if has_converged(_centroids, clusters):
            break
    return clusters
