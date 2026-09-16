def read_record(user, record):
    if not user.can_read(record):
        raise PermissionError("access denied")
    return record.value
