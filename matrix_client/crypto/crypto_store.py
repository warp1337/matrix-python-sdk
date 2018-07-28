import logging
import os
import sqlite3
from collections import defaultdict
from datetime import timedelta
from threading import current_thread

import olm
from appdirs import user_data_dir

from matrix_client.crypto.megolm_outbound_session import MegolmOutboundSession

logger = logging.getLogger(__name__)


class CryptoStore(object):
    """Manages persistent storage for an OlmDevice.

    Args:
        device_id (str): The device id of the OlmDevice.
        db_name (str): Optional. The name of the database file to use. Will be created
            if necessary.
        db_path (str): Optional. The path where to store the database file. Defaults to
            the system default application data directory.
        app_name (str): Optional. The application name, which will be used to determine
            where the database is located. Ignored if db_path is supplied.
        pickle_key (str): Optional. A key to encrypt the database contents.
    """

    def __init__(self,
                 device_id,
                 db_name='crypto.db',
                 db_path=None,
                 app_name='matrix-python-sdk',
                 pickle_key='DEFAULT_KEY'):
        self.device_id = device_id
        data_dir = db_path or user_data_dir(app_name, '')
        try:
            os.makedirs(data_dir)
        except OSError:
            pass
        self.db_filepath = os.path.join(data_dir, db_name)

        # Map from a thread id to a connection object
        self._conn = defaultdict(self.instanciate_connection)
        self.pickle_key = pickle_key
        self.create_tables_if_needed()

    def instanciate_connection(self):
        con = sqlite3.connect(self.db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
        con.row_factory = sqlite3.Row
        return con

    def create_tables_if_needed(self):
        """Ensures all the tables exist."""
        c = self.conn.cursor()
        c.executescript("""
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts (device_id TEXT PRIMARY KEY NOT NULL, account BLOB);
CREATE TABLE IF NOT EXISTS olm_sessions(
    device_id TEXT, session_id TEXT PRIMARY KEY, curve_key TEXT, session BLOB,
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS megolm_inbound_sessions(
    device_id TEXT, session_id TEXT PRIMARY KEY, room_id TEXT, curve_key TEXT,
    session BLOB,
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS megolm_outbound_sessions(
    device_id TEXT, room_id TEXT, session BLOB, max_age_s FLOAT,
    max_messages INTEGER, creation_time TIMESTAMP, message_count INTEGER,
    PRIMARY KEY(device_id, room_id),
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS megolm_outbound_devices(
    device_id TEXT, room_id TEXT, user_device_id TEXT,
    UNIQUE(device_id, room_id, user_device_id),
    FOREIGN KEY(device_id, room_id) REFERENCES
    megolm_outbound_sessions(device_id, room_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS device_keys(
    device_id TEXT, user_id TEXT, user_device_id TEXT, ed_key TEXT,
    curve_key TEXT, PRIMARY KEY(device_id, user_id, user_device_id),
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tracked_users(
    device_id TEXT, user_id TEXT,
    UNIQUE(device_id, user_id),
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sync_tokens(
    device_id TEXT PRIMARY KEY, token TEXT,
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
        """)
        c.close()
        self.conn.commit()

    def save_olm_account(self, account):
        """Saves an Olm account.

        Args:
            account (olm.Account): The account object to save.
        """
        account_data = account.pickle(self.pickle_key)
        c = self.conn.cursor()
        c.execute('INSERT OR IGNORE INTO accounts (device_id, account) VALUES (?,?)',
                  (self.device_id, account_data))
        c.execute('UPDATE accounts SET account=? WHERE device_id=?',
                  (account_data, self.device_id))
        c.close()
        self.conn.commit()

    def get_olm_account(self):
        """Gets the Olm account.

        Returns:
            ``olm.Account`` object, or ``None`` if it wasn't found for the current
            device_id.
        """
        c = self.conn.cursor()
        c.execute(
            'SELECT account FROM accounts WHERE device_id=?', (self.device_id,))
        try:
            account_data = c.fetchone()['account']
            # sqlite gives us unicode in Python2, we want bytes
            account_data = bytes(account_data)
        except TypeError:
            return None
        finally:
            c.close()
        return olm.Account.from_pickle(account_data, self.pickle_key)

    def remove_olm_account(self):
        """Removes the Olm account.

        NOTE: Doing so will remove any saved information associated with the account
        (keys, sessions...)
        """
        c = self.conn.cursor()
        c.execute('DELETE FROM accounts WHERE device_id=?', (self.device_id,))
        c.close()

    def save_olm_session(self, curve_key, session):
        self.save_olm_sessions({curve_key: [session]})

    def save_olm_sessions(self, sessions):
        """Saves Olm sessions.

        Args:
            sessions (defaultdict(list)): A map from curve25519 keys to a list of
                ``olm.Session`` objects.
        """
        c = self.conn.cursor()
        rows = [(self.device_id, s.id, key, s.pickle(self.pickle_key))
                for key in sessions for s in sessions[key]]
        c.executemany('REPLACE INTO olm_sessions VALUES (?,?,?,?)', rows)
        c.close()
        self.conn.commit()

    def load_olm_sessions(self, sessions):
        """Loads all saved Olm sessions.

        Args:
            sessions (defaultdict(list)): A map from curve25519 keys to a list of
                ``olm.Session`` objects, which will be populated.
        """
        c = self.conn.cursor()
        rows = c.execute('SELECT curve_key, session FROM olm_sessions WHERE device_id=?',
                         (self.device_id,))
        for row in rows:
            session = olm.Session.from_pickle(bytes(row['session']), self.pickle_key)
            sessions[row['curve_key']].append(session)
        c.close()

    def get_olm_sessions(self, curve_key, sessions_dict=None):
        """Get the Olm sessions corresponding to a device.

        Args:
            curve_key (str): The curve25519 key of the device.
            sessions_dict (defaultdict(list)): Optional. A map from curve25519 keys to a
                list of ``olm.Session`` objects, to which the session list will be added.

        Returns:
            A list of ``olm.Session`` objects, or ``None`` if none were found.

        NOTE:
            When overriding this, be careful to append the retrieved sessions to the
            list of sessions already present and not to overwrite its reference.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT session FROM olm_sessions WHERE device_id=? AND curve_key=?',
            (self.device_id, curve_key)
        )
        sessions = [olm.Session.from_pickle(bytes(row['session']), self.pickle_key)
                    for row in rows]
        if sessions_dict is not None:
            sessions_dict[curve_key].extend(sessions)
        c.close()
        # For consistency with other get_ methods, do not return an empty list
        return sessions or None

    def save_inbound_session(self, room_id, curve_key, session):
        """Saves a Megolm inbound session.

        Args:
            room_id (str): The room corresponding to the session.
            curve_key (str): The curve25519 key of the device.
            session (olm.InboundGroupSession): The session to save.
        """
        c = self.conn.cursor()
        c.execute('REPLACE INTO megolm_inbound_sessions VALUES (?,?,?,?,?)',
                  (self.device_id, session.id, room_id, curve_key,
                   session.pickle(self.pickle_key)))
        c.close()
        self.conn.commit()

    def load_inbound_sessions(self, sessions):
        """Loads all saved inbound Megolm sessions.

        Args:
            sessions (defaultdict(defaultdict(dict))): An object which will get
                populated with the sessions. The format is
                ``{<room_id>: {<curve25519_key>: {<session_id>:
                <olm.InboundGroupSession>}}}``.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT * FROM megolm_inbound_sessions WHERE device_id=?', (self.device_id,)
        )
        for row in rows:
            session = olm.InboundGroupSession.from_pickle(
                bytes(row['session']), self.pickle_key)
            sessions[row['room_id']][row['curve_key']][session.id] = session
        c.close()

    def get_inbound_session(self, session_id, sessions=None):
        """Gets a saved inbound Megolm session.

        Args:
            room_id (str): The room corresponding to the session.
            curve_key (str): The curve25519 key of the device.
            session_id (str): The id of the session.
            sessions (dict): Optional. A map from session id to
                ``olm.InboundGroupSession`` object, to which the session will be added.

        Returns:
            ``olm.InboundGroupSession`` object, or ``None`` if the session was not found.
        """
        c = self.conn.cursor()
        c.execute(
            'SELECT session FROM megolm_inbound_sessions WHERE session_id=?',
            (session_id,)
        )
        try:
            session_data = c.fetchone()['session']
            session_data = bytes(session_data)
        except TypeError:
            return None
        finally:
            c.close()
        session = olm.InboundGroupSession.from_pickle(session_data, self.pickle_key)
        if sessions is not None:
            sessions[session.id] = session
        return session

    def save_outbound_session(self, room_id, session):
        """Saves a Megolm outbound session.

        Args:
            room_id (str): The room corresponding to the session.
            session (MegolmOutboundSession): The session to save.
        """
        c = self.conn.cursor()
        pickle = session.pickle(self.pickle_key)
        c.execute(
            'INSERT OR IGNORE INTO megolm_outbound_sessions VALUES (?,?,?,?,?,?,?)',
            (self.device_id, room_id, pickle, session.max_age.total_seconds(),
             session.max_messages, session.creation_time, session.message_count)
        )
        c.execute('UPDATE megolm_outbound_sessions SET session=? WHERE device_id=? AND '
                  'room_id=?', (pickle, self.device_id, room_id))
        c.close()
        self.conn.commit()

    def load_outbound_sessions(self, sessions):
        """Loads all saved outbound Megolm sessions.

        Also loads the devices each are shared with.

        Args:
            sessions (dict): A map from room_id to a :class:`.MegolmOutboundSession`
                object, which will be populated.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT * FROM megolm_outbound_sessions WHERE device_id=?', (self.device_id,))
        for row in rows.fetchall():
            device_ids = c.execute(
                'SELECT user_device_id FROM megolm_outbound_devices WHERE device_id=? '
                'AND room_id=?', (self.device_id, row['room_id'])
            )
            devices = {device_id[0] for device_id in device_ids}
            max_age_s = row['max_age_s']
            max_age = timedelta(seconds=max_age_s)
            session = MegolmOutboundSession.from_pickle(
                bytes(row['session']), devices, max_age, row['max_messages'],
                row['creation_time'], row['message_count'], self.pickle_key
            )
            sessions[row['room_id']] = session
        c.close()

    def get_outbound_session(self, room_id, sessions=None):
        """Gets a saved outbound Megolm session.

        Also loads the devices it is shared with.

        Args:
            room_id (str): The room corresponding to the session.
            sessions (dict): Optional. A map from room_id to a
                :class:`.MegolmOutboundSession` object, to which the session will be
                added.

        Returns:
            :class:`.MegolmOutboundSession` object, or ``None`` if the session was
            not found.
        """
        c = self.conn.cursor()
        c.execute(
            'SELECT * FROM megolm_outbound_sessions WHERE device_id=? AND room_id=?',
            (self.device_id, room_id)
        )
        try:
            row = c.fetchone()
            session_data = bytes(row['session'])
        except TypeError:
            c.close()
            return None
        device_ids = c.execute(
            'SELECT user_device_id FROM megolm_outbound_devices WHERE device_id=? '
            'AND room_id=?', (self.device_id, room_id)
        )
        devices = {device_id[0] for device_id in device_ids}
        c.close()
        max_age_s = row['max_age_s']
        max_age = timedelta(seconds=max_age_s)
        session = MegolmOutboundSession.from_pickle(
            session_data, devices, max_age, row['max_messages'], row['creation_time'],
            row['message_count'], self.pickle_key
        )
        if sessions is not None:
            sessions[room_id] = session
        return session

    def remove_outbound_session(self, room_id):
        """Removes a saved outbound Megolm session.

        Args:
            room_id (str): The room corresponding to the session.
        """
        c = self.conn.cursor()
        c.execute('DELETE FROM megolm_outbound_sessions WHERE device_id=? AND room_id=?',
                  (self.device_id, room_id))
        c.close()
        self.conn.commit()

    def save_megolm_outbound_devices(self, room_id, device_ids):
        """Saves devices an outbound Megolm session is shared with.

        Args:
            room_id (str): The room corresponding to the session.
            device_ids (iterable): A list of device ids.
        """
        c = self.conn.cursor()
        rows = [(self.device_id, room_id, device_id) for device_id in device_ids]
        c.executemany(
            'INSERT OR IGNORE INTO megolm_outbound_devices VALUES (?,?,?)', rows)
        c.close()
        self.conn.commit()

    def save_device_keys(self, device_keys):
        """Saves device keys.

        Args:
            device_keys (defaultdict(dict)): The format is ``{<user_id>: {<device_id>:
                {'curve25519': <curve25519_key>, 'ed25519': <ed25519_key>}``.
        """
        c = self.conn.cursor()
        rows = []
        for user_id, devices_dict in device_keys.items():
            for device_id, keys_dict in devices_dict.items():
                rows.append((self.device_id, user_id, device_id, keys_dict['ed25519'],
                             keys_dict['curve25519']))
        c.executemany('REPLACE INTO device_keys VALUES (?,?,?,?,?)', rows)
        c.close()
        self.conn.commit()

    def load_device_keys(self, device_keys):
        """Loads all saved device keys.

        Args:
            device_keys (defaultdict(dict)): An object which will get populated with
                the keys. The format is ``{<user_id>: {<device_id>:
                {'curve25519': <curve25519_key>, 'ed25519': <ed25519_key>}``.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT * FROM device_keys WHERE device_id=?', (self.device_id,))
        for row in rows:
            device_keys[row['user_id']][row['user_device_id']] = {
                'ed25519': row['ed_key'],
                'curve25519': row['curve_key']
            }
        c.close()

    def get_device_keys(self, user_devices, device_keys=None):
        """Gets the devices keys of the specified devices.

        Args:
            user_devices (dict): A map from user ids to a list of device ids.
                If no device ids are given for a user, all will be retrieved.
            device_keys (defaultdict(dict)): Optional. Will be updated with
                the retrieved keys. The format is ``{<user_id>: {<device_id>:
                {'curve25519': <curve25519_key>, 'ed25519': <ed25519_key>}``.

        Returns:
            A ``defaultdict(dict)`` containing the keys, the format is the same as the
            ``device_keys`` argument.
        """
        c = self.conn.cursor()
        rows = []
        for user_id in user_devices:
            if not user_devices[user_id]:
                c.execute(
                    'SELECT * FROM device_keys WHERE device_id=? AND user_id=?',
                    (self.device_id, user_id)
                )
                rows.extend(c.fetchall())
            else:
                for device_id in user_devices[user_id]:
                    c.execute(
                        'SELECT * FROM device_keys WHERE device_id=? AND user_id=? AND '
                        'user_device_id=?', (self.device_id, user_id, device_id)
                    )
                    rows.extend(c.fetchall())
        c.close()
        result = defaultdict(dict)
        for row in rows:
            result[row['user_id']][row['user_device_id']] = {
                'ed25519': row['ed_key'],
                'curve25519': row['curve_key']
            }
        if device_keys is not None and result:
            device_keys.update(result)
        return result

    def save_tracked_users(self, user_ids):
        """Saves tracked users.

        Args:
            user_ids (iterable): The user ids to save.
        """
        c = self.conn.cursor()
        rows = [(self.device_id, user_id) for user_id in user_ids]
        c.executemany('INSERT OR IGNORE INTO tracked_users VALUES (?,?)', rows)
        c.close()
        self.conn.commit()

    def remove_tracked_users(self, user_ids):
        """Removes tracked users.

        Args:
            user_ids (iterable): The user ids to remove.
        """
        c = self.conn.cursor()
        rows = [(user_id,) for user_id in user_ids]
        c.executemany('DELETE FROM tracked_users WHERE user_id=?', rows)
        c.close()
        self.conn.commit()

    def load_tracked_users(self, tracked_users):
        """Loads all tracked users.

        Args:
            tracked_users (set): Will be populated with user ids.
        """
        c = self.conn.cursor()
        rows = c.execute(
            'SELECT user_id FROM tracked_users WHERE device_id=?', (self.device_id,))
        tracked_users.update(row['user_id'] for row in rows)
        c.close()
        return tracked_users

    def save_sync_token(self, sync_token):
        """Saves a sync token.

        Args:
            sync_token (str): The token to save.
        """
        c = self.conn.cursor()
        c.execute('REPLACE INTO sync_tokens VALUES (?,?)', (self.device_id, sync_token))
        c.close()
        self.conn.commit()

    def get_sync_token(self):
        """Gets the saved sync token.

        Returns:
            A string corresponding to the token, or ``None`` if there wasn't any.
        """
        c = self.conn.cursor()
        c.execute('SELECT token FROM sync_tokens WHERE device_id=?', (self.device_id,))
        try:
            return c.fetchone()['token']
        except TypeError:
            return None
        finally:
            c.close()

    def close(self):
        self.conn.close()

    @property
    def conn(self):
        return self._conn[current_thread().ident]
