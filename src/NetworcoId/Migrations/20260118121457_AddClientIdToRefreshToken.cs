using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NetworcoId.Migrations
{
    /// <inheritdoc />
    public partial class AddClientIdToRefreshToken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "client_id",
                table: "refresh_tokens",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "client_id",
                table: "refresh_tokens");
        }
    }
}
