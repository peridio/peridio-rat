defmodule Peridio.CIDRTest do
  use ExUnit.Case
  doctest Peridio.RAT

  alias Peridio.RAT.Network.CIDR

  describe "difference" do
    # l:   [###]
    # r:   [###]
    # ret: []
    test "same range" do
      {:ok, cidr} = CIDR.from_string("10.0.0.0/16")
      assert [] = CIDR.difference(cidr, cidr)
    end

    # l:   [####]
    # r:   ~[##]~
    # ret: []
    test "right within left" do
      {:ok, left} = CIDR.from_string("10.0.0.0/16")
      {:ok, right} = CIDR.from_string("10.0.255.0/24")
      assert [] = CIDR.difference(left, right)
    end

    # l: [###]
    # r:  [###]
    # ret:  [#]
    test "right end exceeds left end" do
      {:ok, left} = CIDR.from_string("10.0.0.0/16")
      {:ok, right} = CIDR.from_string("10.0.255.0/23")
      assert [%{ip_start: {10, 1, 0, 0}, ip_end: {10, 1, 0, 255}}] = CIDR.difference(left, right)
    end

    # l:    [###]
    # r:   [###]
    # ret: [#]
    test "right start exceeds left start" do
      {:ok, left} = CIDR.from_string("10.0.1.0/18")
      {:ok, right} = CIDR.from_string("10.0.0.0/23")

      assert [
               %CIDR{ip_start: {10, 0, 0, 128}, ip_end: {10, 0, 0, 255}},
               %CIDR{ip_start: {10, 0, 0, 64}, ip_end: {10, 0, 0, 127}},
               %CIDR{ip_start: {10, 0, 0, 32}, ip_end: {10, 0, 0, 63}},
               %CIDR{ip_start: {10, 0, 0, 16}, ip_end: {10, 0, 0, 31}},
               %CIDR{ip_start: {10, 0, 0, 8}, ip_end: {10, 0, 0, 15}},
               %CIDR{ip_start: {10, 0, 0, 4}, ip_end: {10, 0, 0, 7}},
               %CIDR{ip_start: {10, 0, 0, 2}, ip_end: {10, 0, 0, 3}},
               %CIDR{ip_start: {10, 0, 0, 1}, ip_end: {10, 0, 0, 1}}
             ] = CIDR.difference(left, right)
    end

    # l:    [##]
    # r:   [####]
    # ret: [#][#]
    test "right start exceeds left start and right end exceeds left end" do
      {:ok, left} = CIDR.from_string("10.0.1.0/18")
      {:ok, right} = CIDR.from_string("10.0.0.0/16")

      assert [
               %CIDR{ip_start: {10, 0, 0, 0}, ip_end: {10, 0, 0, 255}},
               %CIDR{ip_start: {10, 0, 128, 0}, ip_end: {10, 0, 255, 255}},
               %CIDR{ip_start: {10, 0, 96, 0}, ip_end: {10, 0, 127, 255}},
               %CIDR{ip_start: {10, 0, 80, 0}, ip_end: {10, 0, 95, 255}},
               %CIDR{ip_start: {10, 0, 72, 0}, ip_end: {10, 0, 79, 255}},
               %CIDR{ip_start: {10, 0, 68, 0}, ip_end: {10, 0, 71, 255}},
               %CIDR{ip_start: {10, 0, 66, 0}, ip_end: {10, 0, 67, 255}},
               %CIDR{ip_start: {10, 0, 65, 0}, ip_end: {10, 0, 65, 255}}
             ] = CIDR.difference(left, right)
    end

    # l:    [###]
    # r:   [####]
    # ret: [#]
    test "right start exceeds left start and left and right end are the same" do
      {:ok, left} = CIDR.from_string("10.0.255.0/24")
      {:ok, right} = CIDR.from_string("10.0.0.0/16")

      assert [
               %CIDR{ip_start: {10, 0, 254, 0}, ip_end: {10, 0, 254, 255}},
               %CIDR{ip_start: {10, 0, 252, 0}, ip_end: {10, 0, 253, 255}},
               %CIDR{ip_start: {10, 0, 248, 0}, ip_end: {10, 0, 251, 255}},
               %CIDR{ip_start: {10, 0, 240, 0}, ip_end: {10, 0, 247, 255}},
               %CIDR{ip_start: {10, 0, 224, 0}, ip_end: {10, 0, 239, 255}},
               %CIDR{ip_start: {10, 0, 192, 0}, ip_end: {10, 0, 223, 255}},
               %CIDR{ip_start: {10, 0, 128, 0}, ip_end: {10, 0, 191, 255}},
               %CIDR{ip_start: {10, 0, 64, 0}, ip_end: {10, 0, 127, 255}},
               %CIDR{ip_start: {10, 0, 32, 0}, ip_end: {10, 0, 63, 255}},
               %CIDR{ip_start: {10, 0, 16, 0}, ip_end: {10, 0, 31, 255}},
               %CIDR{ip_start: {10, 0, 8, 0}, ip_end: {10, 0, 15, 255}},
               %CIDR{ip_start: {10, 0, 4, 0}, ip_end: {10, 0, 7, 255}},
               %CIDR{ip_start: {10, 0, 2, 0}, ip_end: {10, 0, 3, 255}},
               %CIDR{ip_start: {10, 0, 1, 0}, ip_end: {10, 0, 1, 255}},
               %CIDR{ip_start: {10, 0, 0, 128}, ip_end: {10, 0, 0, 255}},
               %CIDR{ip_start: {10, 0, 0, 64}, ip_end: {10, 0, 0, 127}},
               %CIDR{ip_start: {10, 0, 0, 32}, ip_end: {10, 0, 0, 63}},
               %CIDR{ip_start: {10, 0, 0, 16}, ip_end: {10, 0, 0, 31}},
               %CIDR{ip_start: {10, 0, 0, 8}, ip_end: {10, 0, 0, 15}},
               %CIDR{ip_start: {10, 0, 0, 4}, ip_end: {10, 0, 0, 7}},
               %CIDR{ip_start: {10, 0, 0, 2}, ip_end: {10, 0, 0, 3}},
               %CIDR{ip_start: {10, 0, 0, 1}, ip_end: {10, 0, 0, 1}}
             ] = CIDR.difference(left, right)
    end

    # l:   [###]
    # r:   [####]
    # ret:    [#]
    test "right and left start are the same and right end exceeds left end" do
      {:ok, left} = CIDR.from_string("10.0.0.0/24")
      {:ok, right} = CIDR.from_string("10.0.0.0/16")

      assert [
               %CIDR{ip_start: {10, 0, 128, 0}, ip_end: {10, 0, 255, 255}},
               %CIDR{ip_start: {10, 0, 64, 0}, ip_end: {10, 0, 127, 255}},
               %CIDR{ip_start: {10, 0, 32, 0}, ip_end: {10, 0, 63, 255}},
               %CIDR{ip_start: {10, 0, 16, 0}, ip_end: {10, 0, 31, 255}},
               %CIDR{ip_start: {10, 0, 8, 0}, ip_end: {10, 0, 15, 255}},
               %CIDR{ip_start: {10, 0, 4, 0}, ip_end: {10, 0, 7, 255}},
               %CIDR{ip_start: {10, 0, 2, 0}, ip_end: {10, 0, 3, 255}},
               %CIDR{ip_start: {10, 0, 1, 0}, ip_end: {10, 0, 1, 255}}
             ] = CIDR.difference(left, right)
    end
  end
end
