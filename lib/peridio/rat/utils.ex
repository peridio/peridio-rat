defmodule Peridio.RAT.Utils do
  def generate_random_string(length) do
    length
    |> :crypto.strong_rand_bytes()
    |> Base.encode32(padding: false)
  end

  @doc """
  Returns the differences between two maps as a map containing only the
  different or new values. The resulting map maintains the same structure
  as the input maps, but only includes paths where values differ.

  For nested maps, it recursively compares and returns only the different branches.
  For scalar values, it returns the value from the second map when different.

  ## Examples:
      iex> Peridio.RAT.Utils.diff(
      ...>   %{a: 1, b: %{c: 2, d: 3}, e: 5},
      ...>   %{a: 1, b: %{c: 4, d: 3}, e: 6}
      ...> )
      %{b: %{c: 4}, e: 6}

      iex> Peridio.RAT.Utils.diff(
      ...>   %{nested: %{a: 1, b: 2}, same: 3},
      ...>   %{nested: %{a: 1, b: 3}, same: 3}
      ...> )
      %{nested: %{b: 3}}
  """
  def diff(map1, map2) when is_map(map1) and is_map(map2) do
    (Map.keys(map1) ++ Map.keys(map2))
    |> Enum.uniq()
    |> Enum.reduce(%{}, fn key, acc ->
      value1 = Map.get(map1, key)
      value2 = Map.get(map2, key)

      case {value1, value2} do
        {v1, v2} when is_map(v1) and is_map(v2) ->
          case diff(v1, v2) do
            diff_map when map_size(diff_map) == 0 -> acc
            diff_map -> Map.put(acc, key, diff_map)
          end

        {nil, v2} when not is_nil(v2) ->
          Map.put(acc, key, v2)

        {v1, nil} when not is_nil(v1) ->
          Map.put(acc, key, nil)

        {v1, v2} when v1 != v2 ->
          Map.put(acc, key, v2)

        _ ->
          acc
      end
    end)
  end

  def deep_merge(left, right) when is_map(left) and is_map(right) do
    Map.merge(left, right, &deep_resolve/3)
  end

  @doc """
  Takes a map and a list of keys, returns a list of key-value tuples sorted according
  to the provided key order. Keys not in the sort list are appended at the end
  in their original order.

  ## Examples:
      iex> MapSort.sort_by_keys(
      ...>   %{"name" => "John", "age" => 30, "city" => "NY"},
      ...>   ["age", "name", "country"]
      ...> )
      [{"age", 30}, {"name", "John"}, {"city", "NY"}]

      # With atom keys
      iex> MapSort.sort_by_keys(
      ...>   %{name: "John", age: 30, city: "NY"},
      ...>   ["age", "name"]
      ...> )
      [{:age, 30}, {:name, "John"}, {:city, "NY"}]
  """
  def sort_by_keys(map, sort_keys) when is_map(map) and is_list(sort_keys) do
    # Convert sort_keys to strings for comparison
    string_sort_keys = Enum.map(sort_keys, &to_string/1)

    # Convert all map entries to list of tuples
    map_entries = Map.to_list(map)

    # Split entries into sorted and unsorted
    {sorted_entries, remaining_entries} = split_entries(map_entries, string_sort_keys)

    # Combine sorted entries with remaining entries
    sorted_entries ++ remaining_entries
  end

  # Handle invalid inputs
  def sort_by_keys(_, _), do: raise(ArgumentError, "Expected a map and a list of keys")

  defp split_entries(entries, sort_keys) do
    # Create sorting function based on position in sort_keys
    sort_fn = fn {key, _} ->
      key_str = to_string(key)

      case Enum.find_index(sort_keys, &(&1 == key_str)) do
        # Put at end if not in sort list
        nil -> length(sort_keys)
        idx -> idx
      end
    end

    # Split and sort entries that are in sort_keys
    {sorted, remaining} =
      Enum.split_with(entries, fn {key, _} ->
        key_str = to_string(key)
        Enum.member?(sort_keys, key_str)
      end)

    {Enum.sort_by(sorted, sort_fn), remaining}
  end

  @doc """
  Same as sort_by_keys/2 but returns a map. Note that the order is only guaranteed
  when using Erlang version 21 or later.

  ## Examples:
      iex> MapSort.sort_by_keys_to_map(
      ...>   %{"name" => "John", "age" => 30, "city" => "NY"},
      ...>   ["age", "name", "country"]
      ...> )
      %{"age" => 30, "name" => "John", "city" => "NY"}
  """
  def sort_by_keys_to_map(map, sort_keys) do
    map
    |> sort_by_keys(sort_keys)
    |> Map.new()
  end

  # If it's not a map, we want the value from the right
  defp deep_resolve(_key, left, right) when is_map(left) and is_map(right) do
    deep_merge(left, right)
  end

  # If the right value is nil, keep the left value
  defp deep_resolve(_key, _left, nil), do: nil

  # Otherwise, prefer the right value
  defp deep_resolve(_key, _left, right), do: right
end
