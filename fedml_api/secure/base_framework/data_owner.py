import tf_encrypted as tfe
import torch
from fedml_api.secure.base_framework.encryption_util import decode
import tensorflow as tf


class DataOwner:
    """Contains methods meant to be executed by a data owner.
  Args:
    player_name: `str`, name of the `tfe.player.Player`
                 representing the data owner
    build_update_step: `Callable`, the function used to construct
                       a local federated learning update.
  """

    BATCH_SIZE = 30

    def __init__(self, player_name, local_data, build_update_step):
        self.player_name = player_name
        self.local_data = local_data
        self._build_update_step = build_update_step

    def _build_data_pipeline(self):
        """Build local data pipeline for federated DataOwners."""

        def normalize(image, label):
            # image = image.type(torch.FloatTensor) / 255.0  # torch.float32
            image = tf.cast(image, tf.float32) / 255.0
            return image, label

        dataset = tf.data.Dataset.from_tensor_slices(self.local_data)
        dataset = dataset.map(decode)
        dataset = dataset.map(normalize)
        dataset = dataset.repeat()
        dataset = dataset.batch(self.BATCH_SIZE)
        for next_element in dataset:
            yield next_element

    # @tfe.local_computation
    def compute_gradient(self):
        """Compute gradient given current model parameters and local data."""
        x, y = self._build_data_pipeline()
        grads = self._build_update_step(x, y)

        return grads
