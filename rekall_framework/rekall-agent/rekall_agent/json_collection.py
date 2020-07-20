import arrow
import six

from rekall_lib import registry
from rekall_lib.rekall_types import collections

if six.PY3:
    unicode = str


def _coerce_timestamp(value):
    if isinstance(value, arrow.Arrow):
        return value.float_timestamp

    return float(value)


class JSONCollectionImpl(collections.JSONCollection):
    """A collection which writes its result as JSON."""
    _allowed_types = {
        "int": int,
        "float": float,

        # Dates as epoch timestamps are stored as floats.
        "epoch": _coerce_timestamp,

        "any": lambda x: x  # Used for opaque types that can not be further
                            # processed.
    }

    if six.PY3:
        _allowed_types["unicode"] = str
        _allowed_types["str"] = bytes
    else:
        _allowed_types["unicode"] = unicode  # Unicode data.
        _allowed_types["str"] = str # Used for binary data.

    def __init__(self, *args, **kwargs):
        super(JSONCollectionImpl, self).__init__(*args, **kwargs)
        self._dirty = False
        self.part_number = 0

    @registry.memoize_method
    def _find_table(self, table=None):
        if isinstance(table, (str, unicode)):
            for i in self.tables:
                if i.name == table:
                    return i

        if table is None:
            if len(self.tables) > 1:
                RuntimeError("Collection contains multiple tables and no "
                             "table is specified.")

            return self.tables[0]

        raise RuntimeError("Unknown table %s" % table)

    def sanitize_row(self, row, table=None):
        """Convert the row into primitives.

        The collection can only store primitives and so we must convert the
        objects to these primitives.
        """
        table = self._find_table(table)
        sanitized_row = []

        # Make sure we only collect the columns which are specified. NOTE:
        # The EFilter query must name the columns exactly the same as the
        # collection spec.
        for column in table.columns:
            name = str(column.name)
            try:
                value = row[name]
            except KeyError:
                sanitized_row.append(None)
                continue

            if value is None:
                sanitized_row.append(None)
                continue

            sanitized_row.append(self._allowed_types[
                column.type or "unicode"](value))

        return sanitized_row

    def insert(self, table=None, row=None, **kwargs):
        table_data = self.table_data.setdefault(table or 'default', [])
        table_data.append(self.sanitize_row(row or kwargs, table=table))
        if len(table_data) >= self.max_rows:
            self.flush()

    def start(self):
        self._dirty = True
        return self

    def flush(self):
        if self.table_data:
            self.location.write_file(self.to_json(),
                                     part=self.part_number)
            self.table_data = {}
            self.part_number += 1
