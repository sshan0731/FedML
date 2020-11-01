import numpy as np
import tf_encrypted as tfe
import torch
import tensorflow as tf


class ModelOwner:
    """Contains code meant to be executed by some `ModelOwner` Player.
  Args:
    player_name: `str`, name of the `tfe.player.Player`
                 representing the model owner.
  """

    LEARNING_RATE = 0.1
    ITERATIONS = 60000 // 30

    def __init__(self, player_name):
        self.player_name = player_name

        with tf.device(tfe.get_config().get_player(player_name).device_name):
            self._initialize_weights()

    def _initialize_weights(self):
        # with tf.name_scope("parameters"):
        self.w0 = np.random.normal(size=[28 * 28, 512])
        self.b0 = np.zeros(512)
        self.w1 = np.random.normal(size=[512, 10])
        self.b1 = np.zeros(10)

    #
    def _build_model(self, x, y):
        """Build the model function for federated learning.
    Includes loss calculation and backprop.
    """
        w0 = self.w0.read_value()
        b0 = self.b0.read_value()
        w1 = self.w1.read_value()
        b1 = self.b1.read_value()
        params = (w0, b0, w1, b1)

        layer0 = np.matmul(x, w0) + b0
        layer1 = np.scipy.special.expit(layer0)

        layer2 = np.matmul(layer1, w1) + b1
        predictions = layer2

        loss = np.reduce_mean(
            np.losses.sparse_softmax_cross_entropy(logits=predictions, labels=y)
        )
        grads = np.gradients(ys=loss, xs=params)
        return predictions, loss, grads

    def build_update_step(self, x, y):
        """Build a graph representing a single update step.
    This method will be called once by all data owners
    to create a local gradient computation on their machine.
    """
        _, _, grads = self._build_model(x, y)
        return grads

    # @tfe.local_computation
    def update_model(self, *grads):
        """Perform a single update step.
    This will be performed on the ModelOwner device
    after securely aggregating gradients.
    Args:
      *grads: `tf.Variables` representing the federally computed gradients.
    """
        params = [self.w0, self.b0, self.w1, self.b1]
        # grads = [tf.cast(grad, tf.float32) for grad in grads]
        grads = [grad.type(torch.FloatTensor) for grad in grads]
        with tf.name_scope("update"):
            update_op = tf.group(
                *[
                    param.assign(param - grad * self.LEARNING_RATE)
                    for param, grad in zip(params, grads)
                ]
            )

        with tf.name_scope("validate"):
            x, y = self._build_data_pipeline()
            y_hat, loss = self._build_validation_step(x, y)

            with tf.control_dependencies([update_op]):
                print_loss = tf.print("loss", loss)
                print_expected = tf.print("expect", y, summarize=50)
                print_result = tf.print("result", y_hat, summarize=50)
                return tf.group(print_loss, print_expected, print_result)
