"""reference: https://github.com/tf-encrypted/tf-encrypted/tree/master/examples/federated-learning"""
from fedml_api.secure.base_framework.model_owner import ModelOwner
from fedml_api.secure.base_framework.data_owner import DataOwner
import logging
import argparse
import numpy as np
import torch
import tf_encrypted as tfe
from fedml_api.secure.base_framework.encryption_util import encode
from fedml_api.data_preprocessing.MNIST.data_loader import load_partition_data_mnist


def load_data(args):
    if args.dataset == "mnist":
        logging.info("load_data. dataset_name = %s" % args.dataset)
        client_num, train_data_num, test_data_num, train_data_global, test_data_global, \
        train_data_local_num_dict, train_data_local_dict, test_data_local_dict, \
        class_num = load_partition_data_mnist(args.batch_size)
        args.client_num_in_total = client_num

    dataset = [train_data_num, test_data_num, train_data_global, test_data_global,
               train_data_local_num_dict, train_data_local_dict, test_data_local_dict, class_num]
    return dataset


def encode_data_dict(data_dict, data_num, class_num):
    encrypted_training_data_list = list()
    for i in range(len(data_dict)):
        for idx, (x, labels) in enumerate(data_dict[i]):
            # todo: add encode function
            encrypted_data = encode(x, labels)
            encrypted_training_data_list.append(encrypted_data)
    batch_size = data_num / class_num
    encrypted_data_dict = dict()
    for i in range(class_num):
        encrypted_data_dict[i] = encrypted_training_data_list[i * batch_size: (i + 1) * batch_size]
    return encrypted_data_dict


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
                        help='input batch size for training (default: 1280)')
    parser.add_argument('--data_owner_num', type=int, default=10, metavar='N',
                        help='input # of data owner (default: 10)')
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
    train_data_num, test_data_num, train_data_global, test_data_global, \
    train_data_local_num_dict, train_data_local_dict, test_data_local_dict, class_num \
        = load_data(args)

    # encrypt data
    encrypted_training_data_dict = encode_data_dict(train_data_local_dict, train_data_num, args.data_owner_num)
    encrypted_test_data_dict = encode_data_dict(test_data_local_dict, test_data_num, args.data_owner_num)
    # reference: tf-encrypted - federated learning examples
    model_owner = ModelOwner("model-owner")
    data_owners = []
    for owner_idx in range(class_num):
        data_owner = DataOwner(owner_idx, encrypted_training_data_dict[owner_idx], model_owner.build_update_step)
        data_owners.append(data_owner)
    model_grads = zip(*(data_owner.compute_gradient() for data_owner in data_owners))

    aggregated_model_grads = [
        tfe.add_n(grads) / len(grads) for grads in model_grads
    ]
    iteration_op = model_owner.update_model(*aggregated_model_grads)
