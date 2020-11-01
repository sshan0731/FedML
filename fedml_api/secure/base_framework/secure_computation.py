from fedml_api.secure.base_framework.model_owner import ModelOwner
from fedml_api.secure.base_framework.data_owner import DataOwner
import logging
import sys
import argparse

import numpy as np
import torch
import tf_encrypted as tfe
from fedml_api.secure.base_framework.encryption_util import encode

from fedml_api.data_preprocessing.MNIST.data_loader import load_partition_data_mnist


def load_data(args, dataset_name):
    if dataset_name == "mnist":
        logging.info("load_data. dataset_name = %s" % dataset_name)
        client_num, train_data_num, test_data_num, train_data_global, test_data_global, \
        train_data_local_num_dict, train_data_local_dict, test_data_local_dict, \
        class_num = load_partition_data_mnist(args.batch_size)
        args.client_num_in_total = client_num
    #     todo: transfer to encrypted data
    dataset = [train_data_num, test_data_num, train_data_global, test_data_global,
               train_data_local_num_dict, train_data_local_dict, test_data_local_dict, class_num]
    return dataset


def add_args(parser):
    """
    parser : argparse.ArgumentParser
    return a parser added with args required by fit
    """
    # Training settings
    parser.add_argument('--dataset', type=str, default='mnist', metavar='N',
                        help='dataset used for training')
    parser.add_argument('--data_dir', type=str, default='./../../../data/MNIST',
                        help='data directory')
    parser.add_argument('--batch_size', type=int, default=1280, metavar='N',
                        help='input batch size for training (default: 64)')
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig()
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    args = add_args(argparse.ArgumentParser(description='FedSecure'))
    logger.info(args)

    np.random.seed(0)
    torch.manual_seed(10)

    # load data
    train_data_num, test_data_num, \
    train_data_global, test_data_global, \
    train_data_local_num_dict, train_data_local_dict, \
    test_data_local_dict, class_num \
        = load_data(args, args.dataset)

    # encrypt data
    train_encrypted_data_local_dict = dict()
    for data_owner_idx in train_data_local_dict:  # key: client id
        encrypted_batch_data = list()
        i = 0
        for (x, y) in train_data_local_dict[data_owner_idx]:
            enc_xy = encode(x[i].numpy(), y[i].numpy())
            encrypted_batch_data.append(enc_xy.SerializeToString())
            i = i + 1
        train_encrypted_data_local_dict[data_owner_idx] = encrypted_batch_data

    model_owner = ModelOwner("model-owner")
    data_owners = []
    for owner_idx in range(class_num):

        data_owner = DataOwner(owner_idx, train_encrypted_data_local_dict[owner_idx], model_owner.build_update_step)
        data_owners.append(data_owner)

    model_grads = zip(*(data_owner.compute_gradient() for data_owner in data_owners))

    aggregated_model_grads = [
        tfe.add_n(grads) / len(grads) for grads in model_grads
    ]
    iteration_op = model_owner.update_model(*aggregated_model_grads)

    # with tfe.Session(target=session_target) as sess:
    #     # sess.run(tf.global_variables_initializer(), tag="init")
    #     sess.run(tag="init")
    #
    #     for i in range(model_owner.ITERATIONS):
    #         if i % 100 == 0:
    #             print("Iteration {}".format(i))
    #             sess.run(iteration_op, tag="iteration")
    #         else:
    #             sess.run(iteration_op)
