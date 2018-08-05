# STD
import os
import Queue
import requests
import logging

# SELF
from matrix_client.crypto.encrypt_attachments import decrypt_attachment

logger = logging.getLogger(__name__)


class FileAttachmentHandler(object):
    """Stores events in a queue that have been decrypted previously.

        Has convenience functions for getting last event (user decides to download or not)
        and store the corresponding file in a predefined location.

        Args:
            api (MatrixHttpApi): The api object used to make requests.

        """
    def __init__(self, _api):
        self.api = _api
        # TODO: I guess this does not work on Windows...
        self.who_am_i = os.environ["HOME"]
        # The Queue contains decrypted messages of type 'm.file'
        # TODO: Maxsize? Maxsize <= History?
        self.q = Queue.Queue()
        # TODO: Is there a standard for this, in Riot.im for instance?
        # TODO: User customizable?
        # TODO: Also, make sure the path exists ;)
        self.default_storage_location = self.who_am_i + "/.local/cache/matrix_py_sdk/"

    def add_to_queue(self, _item):
        self.q.put(_item)

    def get_last_event(self):
        if not self.q.empty():
            return self.q.get()
        else:
            logger.warn("Queue is emtpy")
            return None

    def decrypt_attachment_and_save(self, _item):
        encr_file, name, mime_type = self._download_attachment(_item)
        if encr_file is not None and name is not None and mime_type is not None:
            keys = {
                'v': 'v2',
                'key': _item['file']['key'],
                # Send IV concatenated with counter
                'iv': _item['file']['iv'],
                'hashes': _item['file']['hashes']
            }
            decr_file = decrypt_attachment(encr_file, keys)
            path_to_file = self.default_storage_location + name
            f_ = open(path_to_file, 'w')
            f_.write(decr_file)
            f_.close()
            logger.info("Saved attachment %s of type %s to %s" % (name, mime_type, path_to_file))
        else:
            logger.warn("Could not decrypt attachment")

    # TODO: We also might introduce a strict download policy based on the MIME-TYPE, e.g., application/pdf only.
    def _download_attachment(self, _item):
        file_name = _item['body']
        mime_type = _item['info']['mimetype']
        try:
            tmp_url = self.api.get_download_url(_item['file']['url'])
        except ValueError as ve:
            logger.warn("%s" % str(ve))
            return None, None, None
        try:
            encr_file = requests.get(tmp_url)
        except requests.exceptions.RequestException as re:
            logger.warn("%s" % str(re))
            return None, None, None
        return encr_file.content, file_name, mime_type
