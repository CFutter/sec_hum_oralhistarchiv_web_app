"""Read-only validation of public PostgreSQL schema objects against declared contracts.

RuntimeError reports malformed catalog results or structural drift;
database errors propagate. Each query has its own transaction, so
validation requires a schema that is not being changed concurrently.
"""

import re
from collections.abc import Mapping
from dataclasses import replace
from typing import cast

from psycopg.rows import tuple_row
from psycopg_pool import AsyncConnectionPool

from .db import get_db_cursor
from .db_schema_contract import (
    FUNCTION_CONTRACTS,
    TABLE_COLUMN_CONTRACTS,
    TABLE_CONSTRAINT_CONTRACTS,
    TABLE_INDEX_CONTRACTS,
    TRIGGER_CONTRACTS,
    ColumnSpec,
    ConstraintKind,
    ConstraintSpec,
    ForeignKeyAction,
    FunctionParallelMode,
    FunctionSpec,
    FunctionVolatility,
    IdentityMode,
    IndexKeySpec,
    IndexMethod,
    IndexSpec,
    TriggerEnabledMode,
    TriggerSpec,
)

_CONSTRAINT_ROW_LENGTH = 13
_INDEX_ROW_LENGTH = 12
_FUNCTION_ROW_LENGTH = 10
_TRIGGER_ROW_LENGTH = 7

_CONSTRAINT_KINDS: dict[str, ConstraintKind] = {
    "p": "primary_key",
    "u": "unique",
    "c": "check",
    "f": "foreign_key",
}

_FOREIGN_KEY_ACTIONS: dict[str, ForeignKeyAction] = {
    "a": "NO ACTION",
    "r": "RESTRICT",
    "c": "CASCADE",
    "n": "SET NULL",
    "d": "SET DEFAULT",
}


def _index_spec_from_row(
    row: tuple[object, ...],
) -> IndexSpec:
    """Convert the 12-field catalog projection to IndexSpec.

    Raise RuntimeError for wrong length, non-btree/gin methods, unequal
    key metadata lengths, or options outside descending/nulls-first bits.
    """
    if len(row) != _INDEX_ROW_LENGTH:
        raise RuntimeError(
            "Unexpected pg_index query shape: "
            f"expected {_INDEX_ROW_LENGTH} values, found {len(row)}"
        )

    (
        index_name_value,
        unique,
        method,
        key_definitions_value,
        operator_classes_value,
        key_options_value,
        include_columns_value,
        predicate,
        valid,
        ready,
        live,
        nulls_not_distinct,
    ) = row

    index_name = cast(str, index_name_value)
    method_name = cast(str, method)

    if method_name not in {"btree", "gin"}:
        raise RuntimeError(f"Unsupported access method {method_name!r} for index {index_name!r}")

    key_definitions = tuple(cast(list[str], key_definitions_value))
    operator_classes = tuple(cast(list[str], operator_classes_value))
    key_options = tuple(cast(list[int], key_options_value))

    if not (len(key_definitions) == len(operator_classes) == len(key_options)):
        raise RuntimeError(
            f"Inconsistent key metadata for index {index_name!r}: "
            f"{len(key_definitions)} definitions, "
            f"{len(operator_classes)} operator classes, "
            f"{len(key_options)} option values"
        )

    unsupported_options = [option for option in key_options if option & ~3]
    if unsupported_options:
        raise RuntimeError(
            f"Unsupported key options for index {index_name!r}: {unsupported_options}"
        )

    keys = tuple(
        IndexKeySpec(
            definition=definition,
            operator_class=operator_class,
            descending=bool(option & 1),
            nulls_first=bool(option & 2),
        )
        for definition, operator_class, option in zip(
            key_definitions,
            operator_classes,
            key_options,
            strict=True,
        )
    )

    return IndexSpec(
        unique=cast(bool, unique),
        method=cast(IndexMethod, method_name),
        keys=keys,
        include_columns=tuple(cast(list[str], include_columns_value)),
        predicate=cast(str | None, predicate),
        valid=cast(bool, valid),
        ready=cast(bool, ready),
        live=cast(bool, live),
        nulls_not_distinct=cast(bool, nulls_not_distinct),
    )


async def _get_table_index_specs(
    pool: AsyncConnectionPool,
    table_name: str,
) -> dict[str, IndexSpec]:
    """Return named non-constraint indexes for a regular public table.

    Exclude indexes associated with any constraint; parse failures raise
    RuntimeError. A missing table returns an empty mapping.
    """
    async with get_db_cursor(
        pool,
        row_factory=tuple_row,
    ) as cur:
        await cur.execute(
            """
            SELECT
                index_class.relname,
                index_record.indisunique,
                access_method.amname,

                ARRAY(
                    SELECT pg_get_indexdef(
                        index_record.indexrelid,
                        position.number,
                        false
                    )
                    FROM generate_series(
                        1,
                        index_record.indnkeyatts
                    ) AS position(number)
                    ORDER BY position.number
                ),

                ARRAY(
                    SELECT operator_class.opcname::text
                    FROM generate_series(
                        1,
                        index_record.indnkeyatts
                    ) AS position(number)
                    JOIN pg_opclass AS operator_class
                      ON operator_class.oid =
                         index_record.indclass[
                             (position.number - 1)::integer
                         ]
                    ORDER BY position.number
                ),

                ARRAY(
                    SELECT index_record.indoption[
                        (position.number - 1)::integer
                    ]::integer
                    FROM generate_series(
                        1,
                        index_record.indnkeyatts
                    ) AS position(number)
                    ORDER BY position.number
                ),

                ARRAY(
                    SELECT pg_get_indexdef(
                        index_record.indexrelid,
                        position.number,
                        false
                    )
                    FROM generate_series(
                        index_record.indnkeyatts + 1,
                        index_record.indnatts
                    ) AS position(number)
                    ORDER BY position.number
                ),

                pg_get_expr(
                    index_record.indpred,
                    index_record.indrelid,
                    false
                ),
                index_record.indisvalid,
                index_record.indisready,
                index_record.indislive,
                index_record.indnullsnotdistinct

            FROM pg_index AS index_record
            JOIN pg_class AS table_class
              ON table_class.oid = index_record.indrelid
            JOIN pg_namespace AS namespace
              ON namespace.oid = table_class.relnamespace
            JOIN pg_class AS index_class
              ON index_class.oid = index_record.indexrelid
            JOIN pg_am AS access_method
              ON access_method.oid = index_class.relam
            LEFT JOIN pg_constraint AS owner_constraint
              ON owner_constraint.conindid =
                 index_record.indexrelid

            WHERE namespace.nspname = 'public'
              AND table_class.relname = %s
              AND table_class.relkind = 'r'
              AND owner_constraint.oid IS NULL

            ORDER BY index_class.relname
            """,
            (table_name,),
        )
        rows = await cur.fetchall()

    return {cast(str, row[0]): _index_spec_from_row(row) for row in rows}


async def _get_table_column_specs(
    pool: AsyncConnectionPool,
    table_name: str,
) -> dict[str, ColumnSpec]:
    """Return named non-dropped user columns for a regular public table;
    missing tables yield an empty mapping.
    """
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            """
            SELECT
                attribute.attname,
                pg_catalog.format_type(
                    attribute.atttypid,
                    attribute.atttypmod
                ),
                NOT attribute.attnotnull,
                pg_get_expr(
                    default_value.adbin,
                    default_value.adrelid
                ),
                attribute.attidentity
            FROM pg_attribute AS attribute
            JOIN pg_class AS table_class
              ON table_class.oid = attribute.attrelid
            JOIN pg_namespace AS namespace
              ON namespace.oid = table_class.relnamespace
            LEFT JOIN pg_attrdef AS default_value
              ON default_value.adrelid = attribute.attrelid
             AND default_value.adnum = attribute.attnum
            WHERE namespace.nspname = 'public'
              AND table_class.relname = %s
              AND table_class.relkind = 'r'
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
            ORDER BY attribute.attnum
            """,
            (table_name,),
        )
        rows = await cur.fetchall()

    return {
        name: ColumnSpec(
            pg_type=pg_type,
            nullable=nullable,
            default=default,
            identity=cast(IdentityMode, identity),
        )
        for name, pg_type, nullable, default, identity in rows
    }


def _constraint_spec_from_row(
    row: tuple[object, ...],
) -> ConstraintSpec:
    """Convert the 13-field catalog projection to ConstraintSpec.

    Raise RuntimeError for wrong length, unsupported constraint/action
    codes, missing CHECK text, or invalid foreign-table/schema metadata.
    """
    if len(row) != _CONSTRAINT_ROW_LENGTH:
        raise RuntimeError(
            "Unexpected pg_constraint query shape: "
            f"expected {_CONSTRAINT_ROW_LENGTH} values, found {len(row)}"
        )

    (
        constraint_name,
        kind_code,
        columns,
        referenced_table,
        referenced_columns,
        references_application_schema,
        update_action_code,
        delete_action_code,
        definition,
        deferrable,
        initially_deferred,
        validated,
        nulls_not_distinct,
    ) = row

    name = cast(str, constraint_name)
    code = cast(str, kind_code)

    try:
        kind = _CONSTRAINT_KINDS[code]
    except KeyError as exc:
        raise RuntimeError(
            f"Unsupported PostgreSQL constraint type {code!r} for constraint {name!r}"
        ) from exc

    column_names = tuple(cast(list[str], columns))
    is_deferrable = cast(bool, deferrable)
    is_initially_deferred = cast(bool, initially_deferred)
    is_validated = cast(bool, validated)

    if kind == "check":
        if not isinstance(definition, str):
            raise RuntimeError(f"Check constraint {name!r} has no definition")

        return ConstraintSpec(
            kind="check",
            check_definition=definition,
            deferrable=is_deferrable,
            initially_deferred=is_initially_deferred,
            validated=is_validated,
        )

    if kind in {"primary_key", "unique"}:
        return ConstraintSpec(
            kind=kind,
            columns=column_names,
            nulls_not_distinct=cast(bool, nulls_not_distinct),
            deferrable=is_deferrable,
            initially_deferred=is_initially_deferred,
            validated=is_validated,
        )

    if kind == "foreign_key":
        if not isinstance(referenced_table, str):
            raise RuntimeError(f"Foreign-key constraint {name!r} has no referenced table")

        if not isinstance(references_application_schema, bool):
            raise RuntimeError(f"Foreign-key constraint {name!r} has no referenced schema")

        update_code = cast(str, update_action_code)
        delete_code = cast(str, delete_action_code)

        try:
            on_update = _FOREIGN_KEY_ACTIONS[update_code]
            on_delete = _FOREIGN_KEY_ACTIONS[delete_code]
        except KeyError as exc:
            raise RuntimeError(
                f"Unsupported foreign-key action for constraint {name!r}: "
                f"update={update_code!r}, delete={delete_code!r}"
            ) from exc

        return ConstraintSpec(
            kind="foreign_key",
            columns=column_names,
            referenced_table=referenced_table,
            referenced_columns=tuple(cast(list[str], referenced_columns)),
            on_update=on_update,
            on_delete=on_delete,
            references_application_schema=references_application_schema,
            deferrable=is_deferrable,
            initially_deferred=is_initially_deferred,
            validated=is_validated,
        )

    raise RuntimeError(f"Unhandled constraint type {kind!r} for constraint {name!r}")


async def _get_table_constraint_specs(
    pool: AsyncConnectionPool,
    table_name: str,
) -> dict[str, ConstraintSpec]:
    """Return named constraints except NOT NULL for a regular public table;
    missing tables yield an empty mapping.
    """
    async with get_db_cursor(pool, row_factory=tuple_row) as cur:
        await cur.execute(
            """
            SELECT
                constraint_record.conname,
                constraint_record.contype,
                ARRAY(
                    SELECT attribute.attname::text
                    FROM unnest(constraint_record.conkey)
                         WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid =
                            constraint_record.conrelid
                     AND attribute.attnum = key.attnum
                    ORDER BY key.position
                ),
                referenced_table.relname,
                ARRAY(
                    SELECT attribute.attname::text
                    FROM unnest(constraint_record.confkey)
                         WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid =
                            constraint_record.confrelid
                     AND attribute.attnum = key.attnum
                    ORDER BY key.position
                ),
                CASE
                    WHEN constraint_record.confrelid = 0 THEN NULL
                    ELSE referenced_namespace.nspname = 'public'
                END,
                constraint_record.confupdtype,
                constraint_record.confdeltype,
                pg_get_constraintdef(
                    constraint_record.oid,
                    false
                ),
                constraint_record.condeferrable,
                constraint_record.condeferred,
                constraint_record.convalidated,
                COALESCE(constraint_index.indnullsnotdistinct, false)
            FROM pg_constraint AS constraint_record
            LEFT JOIN pg_index AS constraint_index
              ON constraint_index.indexrelid = constraint_record.conindid
            JOIN pg_class AS table_class
              ON table_class.oid = constraint_record.conrelid
            JOIN pg_namespace AS namespace
              ON namespace.oid = table_class.relnamespace
            LEFT JOIN pg_class AS referenced_table
              ON referenced_table.oid =
                    constraint_record.confrelid
            LEFT JOIN pg_namespace AS referenced_namespace
              ON referenced_namespace.oid =
                    referenced_table.relnamespace
            WHERE namespace.nspname = 'public'
              AND table_class.relname = %s
              AND table_class.relkind = 'r'
              AND constraint_record.contype <> 'n'
            ORDER BY constraint_record.conname
            """,
            (table_name,),
        )
        rows = await cur.fetchall()
    return {cast(str, row[0]): _constraint_spec_from_row(row) for row in rows}


async def _get_function_specs(
    pool: AsyncConnectionPool,
    function_names: set[str],
) -> dict[str, FunctionSpec]:
    """Return every public function overload of the supplied names, keyed by identity signature.

    An empty name set skips I/O. RuntimeError rejects wrong row lengths or
    unsupported volatility/parallel codes; unrelated function names are ignored.
    """
    if not function_names:
        return {}

    async with get_db_cursor(
        pool,
        row_factory=tuple_row,
    ) as cur:
        await cur.execute(
            """
            SELECT
                function_record.proname,
                pg_get_function_identity_arguments(
                    function_record.oid
                ),
                pg_get_function_result(
                    function_record.oid
                ),
                language_record.lanname,
                function_record.provolatile,
                function_record.prosecdef,
                function_record.proisstrict,
                function_record.proparallel,
                COALESCE(
                    function_record.proconfig,
                    ARRAY[]::text[]
                ),
                function_record.prosrc
            FROM pg_proc AS function_record
            JOIN pg_namespace AS namespace
              ON namespace.oid =
                    function_record.pronamespace
            JOIN pg_language AS language_record
              ON language_record.oid =
                    function_record.prolang
            WHERE namespace.nspname = 'public'
              AND function_record.proname =
                    ANY(%s::text[])
              AND function_record.prokind = 'f'
            ORDER BY
                function_record.proname,
                pg_get_function_identity_arguments(
                    function_record.oid
                )
            """,
            (sorted(function_names),),
        )
        rows = await cur.fetchall()

    result: dict[str, FunctionSpec] = {}

    for row in rows:
        if len(row) != _FUNCTION_ROW_LENGTH:
            raise RuntimeError(
                "Unexpected pg_proc query shape: "
                f"expected {_FUNCTION_ROW_LENGTH} values, "
                f"found {len(row)}"
            )

        (
            function_name_value,
            identity_arguments_value,
            result_value,
            language_value,
            volatility_value,
            security_definer,
            strict,
            parallel_value,
            configuration_value,
            source_value,
        ) = row

        function_name = cast(str, function_name_value)
        identity_arguments = cast(
            str,
            identity_arguments_value,
        )
        volatility_code = cast(str, volatility_value)
        parallel_code = cast(str, parallel_value)

        if volatility_code not in {"i", "s", "v"}:
            raise RuntimeError(
                f"Unsupported volatility {volatility_code!r} for function {function_name!r}"
            )

        if parallel_code not in {"u", "r", "s"}:
            raise RuntimeError(
                f"Unsupported parallel mode {parallel_code!r} for function {function_name!r}"
            )

        signature = f"{function_name}({identity_arguments})"

        result[signature] = FunctionSpec(
            identity_arguments=identity_arguments,
            result=cast(str, result_value),
            language=cast(str, language_value),
            volatility=cast(
                FunctionVolatility,
                volatility_code,
            ),
            security_definer=cast(
                bool,
                security_definer,
            ),
            strict=cast(bool, strict),
            parallel=cast(
                FunctionParallelMode,
                parallel_code,
            ),
            configuration=tuple(cast(list[str], configuration_value)),
            source=cast(str, source_value),
        )

    return result


def _canonical_check_constraint(spec: ConstraintSpec) -> ConstraintSpec:
    """Normalize only the supported literal varchar-enum CHECK's array-wide casts to element casts.

    Return spec unchanged for other expressions; preserve every other field.
    """
    if spec.kind != "check" or spec.check_definition is None:
        return spec
    match = re.fullmatch(
        r"CHECK \(\(\(([a-z_][a-z_0-9]*)\)::text = ANY "
        r"\(\(ARRAY\[(('[a-z_]+'::character varying)(, '[a-z_]+'::character varying)*)"
        r"\]\)::text\[\]\)\)\)",
        spec.check_definition,
    )
    if match is None:
        return spec
    column, values = match.group(1, 2)
    elements = ", ".join(f"({value})::text" for value in values.split(", "))
    return replace(
        spec,
        check_definition=f"CHECK ((({column})::text = ANY (ARRAY[{elements}])))",
    )


async def assert_table_constraint_contract(
    pool: AsyncConnectionPool,
    table_name: str,
    expected: Mapping[str, ConstraintSpec],
    *,
    allowed_extra_constraints: set[str] | None = None,
) -> None:
    """Raise RuntimeError for missing, unexpected, or changed constraints on a public table.

    allowed_extra_constraints=None permits none; allowed extra names are
    not structurally checked. Normalize the supported varchar-enum CHECK
    cast rewrite before comparison.
    """
    allowed = allowed_extra_constraints or set()
    actual = await _get_table_constraint_specs(pool, table_name)

    expected_names = set(expected)
    actual_names = set(actual)

    missing = expected_names - actual_names
    unexpected = actual_names - expected_names - allowed

    problems: list[str] = []

    if missing:
        problems.append(f"missing constraints: {sorted(missing)}")
    if unexpected:
        problems.append(f"unexpected constraints: {sorted(unexpected)}")

    for constraint_name in sorted(expected_names & actual_names):
        expected_constraint = expected[constraint_name]
        actual_constraint = actual[constraint_name]

        if _canonical_check_constraint(actual_constraint) != _canonical_check_constraint(
            expected_constraint
        ):
            problems.append(
                f"constraint {constraint_name!r}: "
                f"expected {expected_constraint!r}, "
                f"found {actual_constraint!r}"
            )

    if problems:
        raise RuntimeError(f"Schema drift on {table_name!r}: {'; '.join(problems)}")


async def assert_table_column_contract(
    pool: AsyncConnectionPool,
    table_name: str,
    expected: Mapping[str, ColumnSpec],
    *,
    allowed_extra_columns: set[str] | None = None,
) -> None:
    """Raise RuntimeError for missing, unexpected, or changed columns on a public table.

    allowed_extra_columns=None permits none; allowed extra names are not
    structurally checked.
    """
    allowed_extra_columns = allowed_extra_columns or set()
    actual = await _get_table_column_specs(pool, table_name)

    expected_names = set(expected)
    actual_names = set(actual)

    missing = expected_names - actual_names
    unexpected = actual_names - expected_names - allowed_extra_columns

    problems: list[str] = []

    if missing:
        problems.append(f"missing columns: {sorted(missing)}")
    if unexpected:
        problems.append(f"unexpected columns: {sorted(unexpected)}")

    for column_name in sorted(expected_names & actual_names):
        expected_column = expected[column_name]
        actual_column = actual[column_name]

        if actual_column != expected_column:
            problems.append(
                f"column {column_name!r}: expected {expected_column!r}, found {actual_column!r}"
            )

    if problems:
        raise RuntimeError(f"Schema drift on {table_name!r}: {'; '.join(problems)}")


async def assert_table_index_contract(
    pool: AsyncConnectionPool,
    table_name: str,
    expected: Mapping[str, IndexSpec],
    *,
    allowed_extra_indexes: set[str] | None = None,
) -> None:
    """Raise RuntimeError for missing, unexpected, or changed non-constraint public-table indexes.

    allowed_extra_indexes=None permits none; allowed extra names are not
    structurally checked.
    """
    allowed = allowed_extra_indexes if allowed_extra_indexes is not None else set()
    actual = await _get_table_index_specs(pool, table_name)

    expected_names = set(expected)
    actual_names = set(actual)

    missing = expected_names - actual_names
    unexpected = actual_names - expected_names - allowed

    problems: list[str] = []

    if missing:
        problems.append(f"missing indexes: {sorted(missing)}")

    if unexpected:
        problems.append(f"unexpected indexes: {sorted(unexpected)}")

    for index_name in sorted(expected_names & actual_names):
        expected_index = expected[index_name]
        actual_index = actual[index_name]

        if actual_index != expected_index:
            problems.append(
                f"index {index_name!r}: expected {expected_index!r}, found {actual_index!r}"
            )

    if problems:
        raise RuntimeError(f"Schema drift on {table_name!r}: {'; '.join(problems)}")


async def assert_function_contract(
    pool: AsyncConnectionPool,
    expected: Mapping[str, FunctionSpec],
    *,
    allowed_extra_functions: set[str] | None = None,
) -> None:
    """Require matching public function signatures and properties or raise RuntimeError.

    Expected keys use name(identity arguments); malformed keys fail before
    I/O. Inspect all overloads only of expected names. None permits no extra
    overloads; allowed_extra_functions names signatures exempt from comparison.
    """
    allowed = allowed_extra_functions if allowed_extra_functions is not None else set()

    function_names: set[str] = set()

    for signature in expected:
        function_name, separator, _ = signature.partition("(")

        if not separator or not function_name or not signature.endswith(")"):
            raise RuntimeError(f"Invalid function-contract signature: {signature!r}")

        function_names.add(function_name)

    actual = await _get_function_specs(
        pool,
        function_names,
    )

    expected_names = set(expected)
    actual_names = set(actual)

    missing = expected_names - actual_names
    unexpected = actual_names - expected_names - allowed

    problems: list[str] = []

    if missing:
        problems.append(f"missing functions: {sorted(missing)}")

    if unexpected:
        problems.append(f"unexpected function overloads: {sorted(unexpected)}")

    for signature in sorted(expected_names & actual_names):
        expected_function = expected[signature]
        actual_function = actual[signature]

        if actual_function != expected_function:
            problems.append(
                f"function {signature!r}: expected {expected_function!r}, found {actual_function!r}"
            )

    if problems:
        raise RuntimeError(f"Schema drift in managed PostgreSQL functions: {'; '.join(problems)}")


async def _get_table_trigger_specs(
    pool: AsyncConnectionPool,
    table_name: str,
) -> dict[str, TriggerSpec]:
    """Return named non-internal triggers on a regular public table.

    Missing tables yield an empty mapping; invalid row lengths or enabled
    codes raise RuntimeError.
    """
    async with get_db_cursor(
        pool,
        row_factory=tuple_row,
    ) as cur:
        await cur.execute(
            """
            SELECT
                trigger_record.tgname,
                trigger_record.tgenabled,
                trigger_record.tgisinternal,
                trigger_record.tgtype::integer,
                function_namespace.nspname =
                    'public',
                function_record.proname,
                pg_get_triggerdef(
                    trigger_record.oid,
                    false
                )
            FROM pg_trigger AS trigger_record
            JOIN pg_class AS table_class
              ON table_class.oid =
                    trigger_record.tgrelid
            JOIN pg_namespace AS table_namespace
              ON table_namespace.oid =
                    table_class.relnamespace
            JOIN pg_proc AS function_record
              ON function_record.oid =
                    trigger_record.tgfoid
            JOIN pg_namespace AS function_namespace
              ON function_namespace.oid =
                    function_record.pronamespace
            WHERE table_namespace.nspname =
                    'public'
              AND table_class.relname = %s
              AND table_class.relkind = 'r'
              AND NOT trigger_record.tgisinternal
            ORDER BY trigger_record.tgname
            """,
            (table_name,),
        )
        rows = await cur.fetchall()

    result: dict[str, TriggerSpec] = {}

    for row in rows:
        if len(row) != _TRIGGER_ROW_LENGTH:
            raise RuntimeError(
                "Unexpected pg_trigger query shape: "
                f"expected {_TRIGGER_ROW_LENGTH} values, "
                f"found {len(row)}"
            )

        (
            trigger_name_value,
            enabled_value,
            internal,
            trigger_type,
            function_schema_is_application,
            function_name_value,
            definition_value,
        ) = row

        trigger_name = cast(str, trigger_name_value)
        enabled_code = cast(str, enabled_value)

        if enabled_code not in {"O", "D", "R", "A"}:
            raise RuntimeError(
                f"Unsupported enabled mode {enabled_code!r} for trigger {trigger_name!r}"
            )

        result[trigger_name] = TriggerSpec(
            enabled=cast(
                TriggerEnabledMode,
                enabled_code,
            ),
            internal=cast(bool, internal),
            trigger_type=cast(int, trigger_type),
            function_schema_is_application=cast(
                bool,
                function_schema_is_application,
            ),
            function_name=cast(
                str,
                function_name_value,
            ),
            definition=cast(str, definition_value),
        )

    return result


async def assert_table_trigger_contract(
    pool: AsyncConnectionPool,
    table_name: str,
    expected: Mapping[str, TriggerSpec],
    *,
    allowed_extra_triggers: set[str] | None = None,
) -> None:
    """Raise RuntimeError for missing, unexpected, or changed non-internal public-table triggers.

    allowed_extra_triggers=None permits none; allowed extra names are not
    structurally checked.
    """
    allowed = allowed_extra_triggers if allowed_extra_triggers is not None else set()
    actual = await _get_table_trigger_specs(
        pool,
        table_name,
    )

    expected_names = set(expected)
    actual_names = set(actual)

    missing = expected_names - actual_names
    unexpected = actual_names - expected_names - allowed

    problems: list[str] = []

    if missing:
        problems.append(f"missing triggers: {sorted(missing)}")

    if unexpected:
        problems.append(f"unexpected triggers: {sorted(unexpected)}")

    for trigger_name in sorted(expected_names & actual_names):
        expected_trigger = expected[trigger_name]
        actual_trigger = actual[trigger_name]

        if actual_trigger != expected_trigger:
            problems.append(
                f"trigger {trigger_name!r}: expected {expected_trigger!r}, found {actual_trigger!r}"
            )

    if problems:
        raise RuntimeError(f"Schema drift on {table_name!r}: {'; '.join(problems)}")


async def validate_schema_against_db(
    pool: AsyncConnectionPool,
) -> None:
    """Validate all declared table objects and managed function names.

    Raise RuntimeError for unequal contract table sets or live drift. Extra
    tables and functions with unmanaged names are outside this check.
    """
    column_tables = set(TABLE_COLUMN_CONTRACTS)
    constraint_tables = set(TABLE_CONSTRAINT_CONTRACTS)
    index_tables = set(TABLE_INDEX_CONTRACTS)
    trigger_tables = set(TRIGGER_CONTRACTS)

    if not (column_tables == constraint_tables == index_tables == trigger_tables):
        all_tables = column_tables | constraint_tables | index_tables | trigger_tables

        raise RuntimeError(
            "Database contract table sets do not match: "
            "missing column contracts="
            f"{sorted(all_tables - column_tables)}, "
            "missing constraint contracts="
            f"{sorted(all_tables - constraint_tables)}, "
            "missing index contracts="
            f"{sorted(all_tables - index_tables)}, "
            "missing trigger contracts="
            f"{sorted(all_tables - trigger_tables)}"
        )

    for table_name, column_contract in TABLE_COLUMN_CONTRACTS.items():
        await assert_table_column_contract(
            pool,
            table_name,
            column_contract,
        )
        await assert_table_constraint_contract(
            pool,
            table_name,
            TABLE_CONSTRAINT_CONTRACTS[table_name],
        )
        await assert_table_index_contract(
            pool,
            table_name,
            TABLE_INDEX_CONTRACTS[table_name],
        )
        await assert_table_trigger_contract(
            pool,
            table_name,
            TRIGGER_CONTRACTS[table_name],
        )

    await assert_function_contract(
        pool,
        FUNCTION_CONTRACTS,
    )
