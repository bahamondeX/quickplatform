import typing as tp

import typing_extensions as tpe

T = tp.TypeVar("T")
P = tpe.ParamSpec("P")


def singleton(cls: tp.Type[T]) -> tp.Type[T]:
    instance = None

    def get_instance(*args: P.args, **kwargs: P.kwargs) -> T:
        nonlocal instance
        if instance is None:
            instance = cls(*args, **kwargs)
        return instance

    return tp.cast(tp.Type[T], get_instance)
