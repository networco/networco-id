using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NetworcoId.Migrations
{
    /// <inheritdoc />
    public partial class AddUserAddressFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "address_country",
                table: "users",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "address_formatted",
                table: "users",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "address_locality",
                table: "users",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "address_postal_code",
                table: "users",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "address_region",
                table: "users",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "address_street_address",
                table: "users",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "address_country",
                table: "users");

            migrationBuilder.DropColumn(
                name: "address_formatted",
                table: "users");

            migrationBuilder.DropColumn(
                name: "address_locality",
                table: "users");

            migrationBuilder.DropColumn(
                name: "address_postal_code",
                table: "users");

            migrationBuilder.DropColumn(
                name: "address_region",
                table: "users");

            migrationBuilder.DropColumn(
                name: "address_street_address",
                table: "users");
        }
    }
}
